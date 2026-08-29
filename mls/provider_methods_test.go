// The gates over the METHODS of this package that are handed a CryptoProvider.
//
// Every derived provider gate this package already carries reads the package level half of
// the surface and stops there. packageLevelFunctionsIn skips a declaration carrying a
// receiver, and providerConstructions skips one the type checker reads as a method; the
// three gates built on them -- TestEveryConstructionInThisPackageLeavesItsInputAlone,
// TestEveryConstructionHandedAProviderRoutesThroughIt and
// TestEveryConstructionHandedAProviderReadsKdfNhFromIt -- therefore demand nothing of a
// method, and a method cannot be given a row in them even if somebody wanted to.
//
// That is a class boundary rather than an enumeration, and it is the right one for those
// gates: a construction is called by name and a method is called on a receiver, so the two
// need different tables. What was missing is the other half of the partition. A receiver was
// the whole of what it took to sit outside every one of them, and the two methods the
// transcript adds are exactly the shape those gates exist for -- they read KDF.Nh off the
// provider they are handed, they compute the one value a group cannot disagree about and
// recover from, and one of them RETAINS a caller's array for the lifetime of the group.
// Measured, not supposed: nh := crypto.HashSize() replaced by nh := 32 in
// (*TranscriptHashes).SetFromGroupInfo, and its defensive copy of the GroupInfo's confirmed
// transcript hash deleted, each left the whole of mls green.
//
// So this file states the other half. The class is read off the type checker -- every method
// of this package's non test source whose parameters include a CryptoProvider -- each member
// has to have a row, and TestEveryDeclarationTakingAProviderIsHeldByExactlyOneOfTheTwoClasses
// compares the two halves against the whole so a declaration cannot fall between them.
package mls

import (
	"bytes"
	"fmt"
	"go/types"
	"slices"
	"testing"
)

// One value a method left behind, named.
//
// The values are read one at a time rather than concatenated, and that is the difference
// between this gate and a weaker one. A method leaving two values behind, one computed
// through the provider it was handed and one computed through a provider of its own, answers
// a DIFFERENT concatenation over a provider that flips every answer -- the half that routed
// correctly moves and carries the joined comparison with it. Measured, not supposed: with the
// values joined, an Update building its own provider out of a hardcoded suite for the
// confirmed hash and routing only the interim hash through its parameter passed this file.
type providerDrivenMethodValue struct {
	name    string
	content []byte
	// carried marks a value the method was HANDED rather than one it computed. The routing
	// differential is the wrong instrument for one: a copy of an argument is the same bytes
	// over every provider, so requiring it to move would report every possible
	// implementation as defective. The flag is not taken on trust -- the routing gate holds
	// a carried value to being identical across the two providers and every other value to
	// being different, so a flag set on the wrong value fails rather than exempting it.
	carried bool
}

// One method of this package that is handed a provider, and how to drive it.
//
// The row answers what the RECEIVER holds after the call rather than a return value, because
// what these methods are for is state: two of the three answer nothing but an error, and
// every property below -- routing, KDF.Nh and retention -- is a property of what was left
// behind. Bytes the caller owns go through take, so the recorder the retention gate hands in
// sees exactly the arrays a caller would still own after the call and no others.
type providerDrivenMethodRow struct {
	name string
	call func(t *testing.T, crypto CryptoProvider, take func(content []byte) []byte) ([]providerDrivenMethodValue, error)
}

// providerDrivenMethodRows is the table, one row per member of the derived class.
//
// Every value a row is built out of is cut to the provider's own KDF.Nh rather than to 32,
// which is what lets the same rows run over the wide provider below. A row that wrote a
// length down would be refused there for a reason that is this file's rather than the
// method's, and the differential would read as a defect that is not there.
func providerDrivenMethodRows() []providerDrivenMethodRow {
	return []providerDrivenMethodRow{
		// psk.go's ValSem401. The nonce is the receiver's own field rather than a
		// parameter, so it is not taken through the recorder and this row is outside the
		// retention gate's derived class by the same reading that puts it inside the other
		// two: it is handed no caller array it could keep.
		{name: "(*PreSharedKeyId).Validate", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			id := &PreSharedKeyId{
				PskType:  PskTypeExternal,
				PskId:    bytes.Repeat([]byte{0x11}, 16),
				PskNonce: bytes.Repeat([]byte{0x12}, crypto.HashSize()),
			}
			if err := id.Validate(crypto); err != nil {
				return nil, err
			}
			// a validator computes nothing: both values are the ones it was given, which
			// is why the routing gate cannot hold this row at all
			return []providerDrivenMethodValue{
				{name: "PskId", content: id.PskId, carried: true},
				{name: "PskNonce", content: id.PskNonce, carried: true},
			}, nil
		}},
		// the transcript's own advance. Both arguments are the caller's -- the serialized
		// ConfirmedTranscriptHashInput is the framed commit it goes on to verify a signature
		// over, and the confirmation tag is compared against a freshly computed one
		// afterwards -- and both hashes it leaves behind are read.
		//
		// The input is 64 octets: deliberately neither KDF.Nh of the two providers below, so
		// no comparison there reports a coincidence belonging to a length this file chose.
		{name: "(*TranscriptHashes).Update", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			hashes := InitialTranscriptHashes()
			err := hashes.Update(crypto,
				take(bytes.Repeat([]byte{0x21}, 64)),
				take(bytes.Repeat([]byte{0x22}, crypto.HashSize())))
			if err != nil {
				return nil, err
			}
			return []providerDrivenMethodValue{
				{name: "Confirmed", content: hashes.Confirmed},
				{name: "Interim", content: hashes.Interim},
			}, nil
		}},
		// the joiner's seeding, which is the one long lived retention of somebody else's
		// bytes in this package: the confirmed transcript hash it is handed is a field of a
		// decoded GroupInfo whose buffer the caller still owns, and what it keeps is carried
		// into every later epoch of the group.
		//
		// Confirmed is marked carried because it is the GroupInfo's value and not a
		// derivation -- a joiner that recomputed it would hold a hash the group does not.
		// The routing gate therefore reads it as a value that must NOT move across the two
		// providers, which is a real assertion rather than an exemption.
		{name: "(*TranscriptHashes).SetFromGroupInfo", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			nh := crypto.HashSize()
			joiner := InitialTranscriptHashes()
			err := joiner.SetFromGroupInfo(crypto,
				take(bytes.Repeat([]byte{0x31}, nh)),
				take(bytes.Repeat([]byte{0x32}, nh)))
			if err != nil {
				return nil, err
			}
			return []providerDrivenMethodValue{
				{name: "Confirmed", content: joiner.Confirmed, carried: true},
				{name: "Interim", content: joiner.Interim},
			}, nil
		}},
		// the leaf's signing half. What it leaves behind is the signature, which is a
		// signature over the LeafNodeTBS taken through the provider it was handed -- a body
		// that reached for ed25519 itself would answer a signature that verifies against
		// every leaf in this package and against every published tree, because the corpora
		// are all Ed25519, which is the scheme it would have hardcoded.
		//
		// The private key is a fixed 32 octets rather than one drawn through the provider,
		// so this row does not consume a stream some other row is positioned in, and the
		// group id is taken through the recorder because it is the caller's.
		{name: "(*LeafNode).Sign", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			leaf := testLeafNodeOfSource(LeafNodeSourceCommit)
			err := leaf.Sign(crypto, SignaturePrivateKey(take(bytes.Repeat([]byte{0x51}, 32))),
				take([]byte("the group this leaf sits in")), 3)
			if err != nil {
				return nil, err
			}
			return []providerDrivenMethodValue{{name: "Signature", content: leaf.Signature}}, nil
		}},
		// the leaf's verifying half, whose whole answer is a yes or a no. The tagging
		// provider passes VerifyWithLabel through unchanged -- there is nothing in a refusal
		// for a flip to change -- so a row reading a value the verifier left behind could
		// not be separated from a constant, and this row reads the VERDICT instead.
		//
		// The leaf is signed through the same provider it is then verified against, which is
		// what makes the verdict move: over a provider whose signing half flips its answer, a
		// verifier that routed through that provider refuses, and one that reached for
		// ed25519 on its own accepts exactly as it did over the real provider. The receiver
		// carries the signer's own public key, so nothing here fails for a reason that is not
		// the routing.
		{name: "(*LeafNode).VerifySignature", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			signer := SignaturePrivateKey(bytes.Repeat([]byte{0x52}, 32))
			signaturePub, err := signaturePublicKeyOf(signer)
			if err != nil {
				return nil, err
			}
			leaf := testLeafNodeOfSource(LeafNodeSourceCommit)
			leaf.SignatureKey = signaturePub
			groupId := take([]byte("the group this leaf sits in"))
			if err := leaf.Sign(crypto, signer, groupId, 3); err != nil {
				return nil, err
			}
			verdict := []byte("the leaf verifies")
			if refused := leaf.VerifySignature(crypto, groupId, 3); refused != nil {
				verdict = []byte("the leaf is refused: " + refused.Error())
			}
			return []providerDrivenMethodValue{{name: "the verdict", content: verdict}}, nil
		}},
		// tree_hash.go's four, RFC 9420 section 7.8. All four build their tree the same way and
		// none of them touches the provider to do it: newTestTree signs every leaf through the
		// provider it is handed, so a row built on it would be reporting the signer's routing
		// as the hash's. What each row leaves behind is a digest, and a digest is exactly what
		// both differentials can read -- it moves under a provider that flips every answer, and
		// it is KDF.Nh wide under a provider whose hash is one width up.
		{name: "(*RatchetTree).treeHash", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			tree := providerRowRatchetTree(t)
			root, err := rootOf(tree.LeafWidth())
			if err != nil {
				return nil, err
			}
			// the exclusion arm rather than the nil one, so the row drives the parameter the
			// three exported methods never pass and that the section 7.9 parent hash will
			hash, err := tree.treeHash(crypto, root, map[LeafIndex]bool{LeafIndex(1): true})
			if err != nil {
				return nil, err
			}
			return []providerDrivenMethodValue{{name: "the original tree hash at the root", content: hash}}, nil
		}},
		{name: "(*RatchetTree).NodeTreeHash", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			tree := providerRowRatchetTree(t)
			leaf, err := tree.NodeTreeHash(crypto, NodeIndex(0))
			if err != nil {
				return nil, err
			}
			parent, err := tree.NodeTreeHash(crypto, NodeIndex(1))
			if err != nil {
				return nil, err
			}
			// a leaf and a parent, because the two arms of the section 7.8 select are two
			// separate preimages and a method that routed one of them through its parameter
			// is the defect a single value cannot see
			return []providerDrivenMethodValue{
				{name: "the hash of leaf node 0", content: leaf},
				{name: "the hash of parent node 1", content: parent},
			}, nil
		}},
		{name: "(*RatchetTree).TreeHash", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			tree := providerRowRatchetTree(t)
			hash, err := tree.TreeHash(crypto)
			if err != nil {
				return nil, err
			}
			return []providerDrivenMethodValue{{name: "the whole tree's hash", content: hash}}, nil
		}},
		{name: "(*RatchetTree).TreeHashes", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			tree := providerRowRatchetTree(t)
			hashes, err := tree.TreeHashes(crypto)
			if err != nil {
				return nil, err
			}
			if uint32(len(hashes)) != tree.NodeWidth() {
				t.Fatalf("TreeHashes answered %d entries for a %d node tree", len(hashes), tree.NodeWidth())
			}
			// every entry, not the root alone: this method's whole content is that it answers
			// one hash per node, and a row reading one of them would pass over an
			// implementation that computed the rest through a provider of its own
			values := []providerDrivenMethodValue{}
			for x, hash := range hashes {
				values = append(values, providerDrivenMethodValue{
					name:    fmt.Sprintf("the hash of node %d", x),
					content: hash,
				})
			}
			return values, nil
		}},
		// section 7.9's three. ParentHash answers a digest, which the KDF.Nh differential reads
		// the way it reads the four above it -- and which the ROUTING differential does NOT
		// read the way it reads them. That is a limit of this row rather than a property of the
		// method, and it is written down because a row that looks like the four above it will
		// otherwise be trusted to hold what they hold.
		//
		// The preimage a parent hash is taken over already carries a provider-derived value:
		// the original tree hash of the sibling subtree. So this row's output moves across the
		// two providers whether the FINAL crypto.Hash call routed or not, and a body that took
		// that last digest with crypto/sha256 directly passes the routing gate. Measured, not
		// supposed -- `return crypto.Hash(input), nil` replaced by sha256.Sum256 left
		// TestEveryMethodHandedAProviderRoutesThroughIt green. The routing differential still
		// holds everything UNDER the final call, which is most of the method, and that is what
		// this row is worth.
		//
		// What holds the final call is the KDF.Nh row below -- sha256 answers 32 octets over a
		// provider whose Nh is 48 -- together with
		// TestTheParentHashIsTheProvidersHashOfTheHandDerivedParentHashInput, which compares
		// this method's answer against the tagging provider's own hash of the same hand written
		// octets. Neither is redundant with the other, and the difference is what each reads:
		// the Nh row reads a WIDTH, over a provider whose Nh is not 32 and which the golden does
		// not install; the golden reads the BYTES, which the Nh row never compares. A digest of
		// the right width taken outside the provider is visible only to the golden.
		{name: "(*RatchetTree).ParentHash", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			tree := providerRowRatchetTree(t)
			// both copath children of node 1, because "with respect to the copath child" is
			// the whole mechanism of a parent hash and a row reading one of the two would
			// pass over a body that hashed the same subtree whichever child it was handed
			withRight, err := tree.ParentHash(crypto, NodeIndex(1), NodeIndex(2))
			if err != nil {
				return nil, err
			}
			withLeft, err := tree.ParentHash(crypto, NodeIndex(1), NodeIndex(0))
			if err != nil {
				return nil, err
			}
			return []providerDrivenMethodValue{
				{name: "the parent hash of node 1 with copath child 2", content: withRight},
				{name: "the parent hash of node 1 with copath child 0", content: withLeft},
			}, nil
		}},
		// the other two answer a verdict and a count rather than bytes, so what they leave
		// behind is rendered. Both are driven over a tree whose chain was built through a
		// provider FIXED in the fixture rather than through the row's, which is what makes the
		// answer move: a body that took its hashes from somewhere other than the provider it
		// was handed reproduces that fixed chain under every provider and answers "verifies"
		// to all of them.
		//
		// The renderings are deliberately neither 32 nor 64 octets long, so the KDF.Nh
		// differential reads them as the non-digests they are rather than as a width that
		// failed to follow the provider.
		{name: "(*RatchetTree).parentHashClaimsUnder", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			tree := providerRowChainedRatchetTree(t)
			claims, err := tree.parentHashClaimsUnder(crypto, tree.ParentAt(NodeIndex(1)),
				NodeIndex(1), NodeIndex(0), NodeIndex(2))
			if err != nil {
				return nil, err
			}
			return []providerDrivenMethodValue{
				{name: "the claim count", content: []byte(fmt.Sprintf("claimants: %d", claims))},
			}, nil
		}},
		{name: "(*RatchetTree).VerifyParentHashes", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			tree := providerRowChainedRatchetTree(t)
			verdict := []byte("the parent hashes verify")
			if refused := tree.VerifyParentHashes(crypto); refused != nil {
				verdict = []byte("the parent hashes are refused")
			}
			return []providerDrivenMethodValue{{name: "the verdict", content: verdict}}, nil
		}},
		// task 18's path generation, which is the one member of this class that mutates its
		// receiver and the one that samples entropy.
		//
		// The three values are all KDF.Nh wide and none of them is a public key, which is this
		// row's whole shape. X25519 fixes an HPKE public key at 32 octets whatever the kdf does,
		// so a row reporting one of the path's public keys would be read by the KDF.Nh
		// differential as a length written down rather than as the key it is -- the same
		// coincidence constructionsWhoseAnswerOnlyCoincidesWithKdfNh names for DeriveKeyPair.
		//
		// The ROUTING differential is weak over this row, and that is written down rather than
		// left to be discovered by somebody who reads it as one of the rows above. Every value
		// here descends from crypto.Random, so all three move across a provider that flips every
		// answer whether or not the ladder, the key derivation or the hash routed through the
		// parameter. What holds those instead is the KDF.Nh row -- a commit secret or a parent
		// hash taken outside the provider stays 32 octets over a provider whose Nh is 48 -- and
		// TestTheParentHashChainOfRfc9420AppendixBsWorkedExample, which compares the BYTES of the
		// chain this method writes against preimages spelled out from the RFC's own notation.
		//
		// The signer comes from a provider FIXED in the row rather than from the one under test,
		// because it is a caller's array here: what this method does with it is hand it to
		// SignWithLabel, and generating it through the parameter would make the retention gate
		// read a key the method never received from its caller.
		{name: "(*RatchetTree).CreateUpdatePathSecrets", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			fixed := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
			signer, _, err := fixed.SignatureKeyPair()
			if err != nil {
				return nil, err
			}
			tree := providerRowRatchetTree(t)
			plan, err := tree.CreateUpdatePathSecrets(crypto, LeafIndex(0),
				SignaturePrivateKey(take(signer)), take([]byte("provider-row-group-id")))
			if err != nil {
				return nil, err
			}
			if len(plan.PathSecrets) == 0 {
				return nil, fmt.Errorf("the row's tree gave leaf 0 an empty filtered direct path, so this row observes nothing")
			}
			return []providerDrivenMethodValue{
				{name: "the commit secret", content: plan.CommitSecret},
				{name: "the path secret of the topmost node", content: plan.PathSecrets[len(plan.PathSecrets)-1]},
				{name: "the leaf's parent hash", content: plan.LeafNode.ParentHash},
			}, nil
		}},
		// treekem.go's two. NodePrivateKey has both arms driven, because they are two
		// different answers and only one of them is derived: the node key comes back through
		// the provider and moves, and the member's own leaf key is STORED and must not. The
		// carried flag on the second is a real assertion rather than an exemption -- the gate
		// requires a carried value to be identical across the two providers -- and it is what
		// says the leaf arm answers the key it holds rather than deriving one from a rung of
		// the ladder, which is the confusion the file header of treekem.go is about.
		//
		// Both answers are RENDERED rather than returned raw. An X25519 private key is 32
		// octets whatever the kdf is, so a row answering the key itself would report a
		// coincidence to the KDF.Nh gate that belongs to the KEM and not to this method.
		{name: "(*TreeKEMPrivate).NodePrivateKey", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			state := NewTreeKEMPrivate(LeafIndex(0), HpkePrivateKey(bytes.Repeat([]byte{0x91}, 32)))
			state.PathSecrets[NodeIndex(1)] = bytes.Repeat([]byte{0x92}, crypto.HashSize())
			derived, held, err := state.NodePrivateKey(crypto, NodeIndex(1))
			if err != nil {
				return nil, err
			}
			if !held {
				t.Fatal("the row holds a path secret for node 1 and NodePrivateKey answered that it has none")
			}
			own, held, err := state.NodePrivateKey(crypto, LeafIndex(0).NodeIndex())
			if err != nil {
				return nil, err
			}
			if !held {
				t.Fatal("NodePrivateKey answered that the member does not hold its own leaf key")
			}
			return []providerDrivenMethodValue{
				{name: "the key derived from the path secret at node 1", content: []byte("derived: " + HexOf(derived))},
				{name: "the member's own leaf key", content: []byte("own leaf: " + HexOf(own)), carried: true},
			}, nil
		}},
		// the private state's agreement with the tree, driven over a tree whose node key was
		// derived through a provider fixed HERE rather than through the row's. That is
		// providerRowChainedRatchetTree's reason one construction along: a tree keyed with the
		// row's own provider agrees with itself under every provider, so the verdict would be
		// the same over the real one and the tagging one and the differential would read
		// nothing. Built against a fixed provider, "agrees" is the answer only while the
		// method derives through the provider it was handed.
		//
		// The two renderings are deliberately neither 32 nor 48 octets long, so the KDF.Nh
		// differential reads them as the non-digests they are.
		{name: "(*TreeKEMPrivate).Consistent", call: func(t *testing.T, crypto CryptoProvider, take func([]byte) []byte) ([]providerDrivenMethodValue, error) {
			fixed := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
			pathSecret := bytes.Repeat([]byte{0x93}, fixed.HashSize())
			_, pub, err := DeriveNodeKeyPair(fixed, pathSecret)
			if err != nil {
				return nil, err
			}
			tree := providerRowRatchetTree(t)
			if err := tree.SetParent(NodeIndex(1), &ParentNode{EncryptionKey: pub}); err != nil {
				return nil, err
			}
			state := NewTreeKEMPrivate(LeafIndex(0), HpkePrivateKey(bytes.Repeat([]byte{0x94}, 32)))
			state.PathSecrets[NodeIndex(1)] = pathSecret
			verdict := []byte("Consistent: the path secret derives the key the tree carries")
			if refused := state.Consistent(crypto, tree); refused != nil {
				verdict = []byte("Consistent: refused")
			}
			return []providerDrivenMethodValue{{name: "the verdict", content: verdict}}, nil
		}},
	}
}

// providerRowChainedRatchetTree is providerRowRatchetTree's two leaf cousin, carrying one valid
// RFC 9420 section 7.9.1 parent hash chain.
//
// The chain is computed through a provider fixed HERE and not through the one the row is being
// driven with, and that is the whole point of the fixture. A tree whose chain was built with the
// row's own provider chains under every provider, so the verdict it produces is the same over
// the real one and over the tagging one, and the routing differential would have nothing to
// read. Built once against a fixed provider, the verdict is "verifies" for a body that hashes
// through the provider it was handed and "verifies" for one that hardcoded SHA-256 only when
// those two providers agree -- which is exactly the separation the gate is after.
func providerRowChainedRatchetTree(t *testing.T) *RatchetTree {
	t.Helper()
	fixed := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	tree := NewRatchetTree()
	for _, i := range []LeafIndex{0, 1} {
		leaf := testLeafNodeOfSource(LeafNodeSourceUpdate)
		leaf.EncryptionKey = HpkePublicKey(bytes.Repeat([]byte{0x60 + byte(i)}, 32))
		leaf.SignatureKey = SignaturePublicKey(bytes.Repeat([]byte{0x70 + byte(i)}, 32))
		if err := tree.SetLeaf(i, leaf); err != nil {
			t.Fatalf("SetLeaf(%d): %v", i, err)
		}
	}
	// node 1 is the root of a two leaf tree, so section 7.9 gives it the zero-length
	// parent_hash field and the chain is one link long.
	if err := tree.SetParent(NodeIndex(1), &ParentNode{
		EncryptionKey: HpkePublicKey(bytes.Repeat([]byte{0x61}, 32)),
		ParentHash:    []byte{},
	}); err != nil {
		t.Fatalf("SetParent(1): %v", err)
	}
	hash, err := tree.ParentHash(fixed, NodeIndex(1), NodeIndex(2))
	if err != nil {
		t.Fatalf("ParentHash: %v", err)
	}
	claimant := testLeafNodeOfSource(LeafNodeSourceCommit)
	claimant.EncryptionKey = HpkePublicKey(bytes.Repeat([]byte{0x60}, 32))
	claimant.SignatureKey = SignaturePublicKey(bytes.Repeat([]byte{0x70}, 32))
	claimant.ParentHash = hash
	if err := tree.SetLeaf(LeafIndex(0), claimant); err != nil {
		t.Fatalf("SetLeaf(0): %v", err)
	}
	// the fixture's own claim, so a row driven over this tree cannot be reading a refusal that
	// was already there before the provider was varied
	if err := tree.VerifyParentHashes(fixed); err != nil {
		t.Fatalf("the row's tree does not verify under the provider its chain was built with: %v", err)
	}
	return tree
}

// providerRowRatchetTree is the tree the four tree hash rows run over, built without touching a
// provider at all.
//
// Three occupied leaves in a four wide tree with one parent node set, which is the smallest
// shape that reaches both arms of the section 7.8 select and both kinds of position on each:
// an occupied leaf, a blank leaf, an occupied parent and a blank parent. The leaves carry
// filler key material because nothing here verifies them -- what these rows read is a digest --
// and signing them through the provider under test is exactly what would make the routing
// differential report the signer rather than the hash.
func providerRowRatchetTree(t *testing.T) *RatchetTree {
	tree := NewRatchetTree()
	for _, i := range []LeafIndex{0, 1, 3} {
		// this file's own encodable leaf, with its two keys moved apart per index so no two
		// leaves of the tree hash alike for a reason that is their position rather than their
		// content. The source is update because that arm carries neither a lifetime nor a
		// parent hash, so the leaf encodes with nothing that has to be made up.
		leaf := testLeafNodeOfSource(LeafNodeSourceUpdate)
		leaf.EncryptionKey = HpkePublicKey(bytes.Repeat([]byte{0x20 + byte(i)}, 32))
		leaf.SignatureKey = SignaturePublicKey(bytes.Repeat([]byte{0x30 + byte(i)}, 32))
		if err := tree.SetLeaf(i, leaf); err != nil {
			t.Fatalf("SetLeaf(%d): %v", i, err)
		}
	}
	if err := tree.SetParent(NodeIndex(1), &ParentNode{
		EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{0x51}, 32)),
		UnmergedLeaves: []LeafIndex{1},
	}); err != nil {
		t.Fatalf("SetParent(1): %v", err)
	}
	if tree.NodeWidth() != 7 {
		t.Fatalf("the row's tree is %d nodes wide, want 7", tree.NodeWidth())
	}
	return tree
}

// providerDrivenMethods is every method this package's non test source declares whose
// parameters include a CryptoProvider, read off the type checker.
//
// The same reading providerConstructions makes, with the receiver filter turned the other
// way round. It is the compiler's view of the signature rather than the spelling the line
// gives the parameter, so a method taking an interface that embeds the provider is a member
// of the class and a method taking something merely named CryptoProvider is not.
//
// Absence is fatal, for the reason every other derivation here is: a filter that stopped
// matching leaves the gates reading it demanding nothing, and a gate that demands nothing
// reports exactly what a complete one reports.
func providerDrivenMethods(t *testing.T) []declaredFunction {
	t.Helper()
	provider := providerInterfaceType(t)
	methods := []declaredFunction{}
	for _, function := range declaredFunctionsOf(t, cryptoOwnRoot) {
		if !function.method || len(function.takes(provider)) == 0 {
			continue
		}
		methods = append(methods, function)
	}
	if len(methods) == 0 {
		t.Fatalf("no method of this package takes a %s, so every gate in this file demands nothing",
			providerInterfaceName)
	}
	return methods
}

// The names of those methods, sorted.
func providerDrivenMethodNames(t *testing.T) []string {
	t.Helper()
	names := []string{}
	for _, method := range providerDrivenMethods(t) {
		names = append(names, method.name)
	}
	slices.Sort(names)
	return names
}

// isByteSliceType reports whether the compiler reads a type as a slice of octets, under
// whatever name it is spelled.
//
// Underlying on both halves is what makes a named storage type a member: HpkePublicKey is a
// caller's array exactly as a []byte is, and a filter matching the spelling alone would drop
// it. The element is compared as a kind rather than as a name, because byte and uint8 are one
// type written two ways.
func isByteSliceType(of types.Type) bool {
	slice, isSlice := of.Underlying().(*types.Slice)
	if !isSlice {
		return false
	}
	element, isBasic := slice.Elem().Underlying().(*types.Basic)
	return isBasic && element.Kind() == types.Uint8
}

// providerDrivenMethodNamesTakingCallerBytes is the subset of the class above that is handed
// an array the caller still owns.
//
// Derived rather than listed, and derived as the property itself: a method handed no byte
// slice cannot write into a caller's array and cannot keep one, so it is outside the
// retention gate by what its signature is rather than by an excuse somebody wrote.
func providerDrivenMethodNamesTakingCallerBytes(t *testing.T) []string {
	t.Helper()
	names := []string{}
	for _, method := range providerDrivenMethods(t) {
		for i := 0; i < method.signature.Params().Len(); i++ {
			if isByteSliceType(method.signature.Params().At(i).Type()) {
				names = append(names, method.name)
				break
			}
		}
	}
	if len(names) == 0 {
		t.Fatalf("no method of this package is handed both a %s and a caller's array, so the retention gate demands nothing",
			providerInterfaceName)
	}
	slices.Sort(names)
	return names
}

// The rows this file declares, checked against the class and answered in the class's order.
//
// Both directions are checked. A member with no row is a method nothing below runs, and a row
// naming a method this package does not declare is a row that outlived what it covered.
func providerDrivenMethodRowsFor(t *testing.T, gate string, class []string) []providerDrivenMethodRow {
	t.Helper()
	byName := map[string]providerDrivenMethodRow{}
	for _, row := range providerDrivenMethodRows() {
		if _, repeated := byName[row.name]; repeated {
			t.Fatalf("providerDrivenMethodRows declares %s twice, so one of the two is never run", row.name)
		}
		byName[row.name] = row
	}
	declared := providerDrivenMethodNames(t)
	for name := range byName {
		if !slices.Contains(declared, name) {
			t.Errorf("providerDrivenMethodRows names %s, and no method of this package takes a %s under that name",
				name, providerInterfaceName)
		}
	}
	rows := []providerDrivenMethodRow{}
	for _, name := range class {
		row, written := byName[name]
		if !written {
			t.Errorf("%s: %s is handed a %s and has no row, so nothing holds it",
				gate, name, providerInterfaceName)
			continue
		}
		rows = append(rows, row)
	}
	return rows
}

// A method handed a provider that the routing gate cannot hold, named with the reason. Every
// name here is checked against the derived class below, AND against the row's own shape, so
// an entry cannot outlive the method it excuses and cannot excuse one that has provider
// derived state to compare.
var providerDrivenMethodsOverAnyProvider = map[string]string{
	// Validate reaches the provider for a length and for nothing else, and leaves nothing
	// behind but what it was given. The tagging provider passes HashSize through -- it has
	// no bytes to flip in an int -- so what this holds after a call over the tagging
	// provider is what it holds after a call over the real one, and a row here would report
	// "did not route through its provider" for every possible implementation. It is the
	// same limit labelConstructionsOverAnyProvider records for ZeroSecret, and it is not
	// unheld: the KDF.Nh gate below holds the length it refuses against a provider whose Nh
	// is not 32, which is the whole of what it uses the provider for.
	"(*PreSharedKeyId).Validate": "reads a length off the provider and nothing else, so a provider that flips every answer cannot separate it from a literal",
}

// TestEveryMethodHandedAProviderRoutesThroughIt is
// TestEveryConstructionHandedAProviderRoutesThroughIt over the other half of the partition.
//
// The property is the one the parameter exists for. A method that reached for crypto/sha256
// directly, or built a provider out of a hardcoded suite, agrees with every corpus in this
// package, because the corpora are all X25519/SHA-256 -- the suite it would have hardcoded.
// It matters most on the transcript: the transcript is the one value a group cannot disagree
// about and recover from, so a hash taken under a suite of the method's own choosing is a
// permanent fork rather than a retryable failure.
//
// What separates the two is a provider that answers differently. Over the tagging provider a
// value the method derived through its parameter moves, and one it derived through a provider
// of its own does not. Each value is compared on its own, because a method that routed one of
// two through its parameter is exactly the defect a joined comparison cannot see.
func TestEveryMethodHandedAProviderRoutesThroughIt(t *testing.T) {
	class := providerDrivenMethodNames(t)
	want := []string{}
	for _, name := range class {
		if _, isExcused := providerDrivenMethodsOverAnyProvider[name]; !isExcused {
			want = append(want, name)
		}
	}
	// the provider underneath draws from a constant reader so nothing a row reaches can
	// answer differently on a second call for a reason that is the entropy's
	plain := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, constantReader{value: 0x35})
	held := func(row providerDrivenMethodRow, crypto CryptoProvider) []providerDrivenMethodValue {
		values, err := row.call(t, crypto, func(content []byte) []byte { return content })
		if err != nil {
			t.Fatalf("%s: %v", row.name, err)
		}
		return values
	}
	compared := 0
	for _, row := range providerDrivenMethodRowsFor(t, "the routing gate", want) {
		tagging := &taggingCryptoProvider{inner: plain}
		// with a panic caught rather than taken, for the reason recoveringRow gives: a row
		// that panics on inputs this test chose would otherwise take the test binary down
		// and every gate declared after this one with it
		overTheRealProvider, raised := recoveringRow(func() []providerDrivenMethodValue { return held(row, plain) })
		if raised != nil {
			t.Errorf("%s panicked with %v rather than answering", row.name, raised)
			continue
		}
		overTheTaggingProvider, raised := recoveringRow(func() []providerDrivenMethodValue { return held(row, tagging) })
		if raised != nil {
			t.Errorf("%s panicked with %v over the tagging provider; it called %v", row.name, raised, tagging.calls)
			continue
		}
		if len(overTheRealProvider) == 0 || len(overTheTaggingProvider) != len(overTheRealProvider) {
			t.Errorf("%s left %d values behind over the real provider and %d over the tagging one, so nothing below is compared",
				row.name, len(overTheRealProvider), len(overTheTaggingProvider))
			continue
		}
		derived := 0
		for i, value := range overTheRealProvider {
			flipped := overTheTaggingProvider[i]
			if len(value.content) == 0 {
				t.Errorf("%s left nothing behind in %s, so that value observed nothing", row.name, value.name)
				continue
			}
			if value.carried {
				if !bytes.Equal(value.content, flipped.content) {
					t.Errorf("%s is named as carrying %s through rather than deriving it, and it came back %x over the real provider and %x over one that flips every answer",
						row.name, value.name, value.content, flipped.content)
				}
				continue
			}
			derived++
			if bytes.Equal(value.content, flipped.content) {
				t.Errorf("%s left the same %s behind over a provider that flips every answer, so that value did not route through the provider it was handed; it called %v",
					row.name, value.name, tagging.calls)
			}
		}
		if derived == 0 {
			t.Errorf("%s leaves nothing behind that it derived, so this row holds it to nothing; excuse it in providerDrivenMethodsOverAnyProvider or give it a value to compare",
				row.name)
			continue
		}
		compared++
	}
	// and the excuse is held to the row's own shape as well as to the class: a method left
	// out of the differential must have nothing for the differential to read
	for name, reason := range providerDrivenMethodsOverAnyProvider {
		if !slices.Contains(class, name) {
			t.Errorf("the gate excuses %s, and no method of this package takes a %s under that name",
				name, providerInterfaceName)
			continue
		}
		for _, row := range providerDrivenMethodRows() {
			if row.name != name {
				continue
			}
			for _, value := range held(row, plain) {
				if !value.carried {
					t.Errorf("%s is excused from the routing differential as %q, and its row leaves %s behind as a derived value, which the differential could have held",
						name, reason, value.name)
				}
			}
		}
	}
	if compared != len(want) {
		t.Fatalf("%d of the %d methods the routing differential covers were compared", compared, len(want))
	}
	t.Logf("%d of the %d methods handed a %s held to routing through it", len(want), len(class), providerInterfaceName)
}

// TestEveryMethodHandedAProviderReadsKdfNhFromIt is the differential the registered suites
// cannot supply, over the method half of the partition.
//
// Both registered suites fix KDF.Nh at 32, so nothing already in this tree separates a method
// that reads the length off the provider it was handed from one that writes 32 down. The
// second provider is the registered suite with its whole hash and kdf surface one width up,
// and the rows are cut to whichever provider they are running under.
//
// Two things are compared, because KDF.Nh governs two separate things here. A method that
// wrote the length down REFUSES an input cut to the wide provider's own Nh, which is the
// refusal the first half reads; and a method that read the provider for its refusal and wrote
// 32 down for what it produced leaves a value of the wrong width behind, which is what
// kdfNhCoincidences reads. Either half alone is satisfiable by the other mistake.
func TestEveryMethodHandedAProviderReadsKdfNhFromIt(t *testing.T) {
	class := providerDrivenMethodNames(t)
	narrow := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, constantReader{value: 0x35})
	wide := &wideKdfProvider{CryptoProvider: narrow}
	if narrow.HashSize() == wide.HashSize() {
		t.Fatalf("both providers answer KDF.Nh %d, so every row below compares a length against itself",
			narrow.HashSize())
	}
	contents := func(values []providerDrivenMethodValue) [][]byte {
		out := [][]byte{}
		for _, value := range values {
			out = append(out, value.content)
		}
		return out
	}
	compared := 0
	for _, row := range providerDrivenMethodRowsFor(t, "the KDF.Nh gate", class) {
		overTheNarrowProvider, err := row.call(t, narrow, func(content []byte) []byte { return content })
		if err != nil {
			t.Errorf("%s refused inputs cut to the narrow provider's KDF.Nh of %d: %v",
				row.name, narrow.HashSize(), err)
			continue
		}
		overTheWideProvider, err := row.call(t, wide, func(content []byte) []byte { return content })
		if err != nil {
			t.Errorf("%s refused inputs cut to the KDF.Nh of %d the provider it was handed answers, so it is holding a length of its own rather than reading that provider: %v",
				row.name, wide.HashSize(), err)
			continue
		}
		if len(overTheNarrowProvider) == 0 || len(overTheWideProvider) != len(overTheNarrowProvider) {
			t.Errorf("%s left %d values behind over the narrow provider and %d over the wide one, so nothing below is compared",
				row.name, len(overTheNarrowProvider), len(overTheWideProvider))
			continue
		}
		for _, at := range kdfNhCoincidences(contents(overTheNarrowProvider), contents(overTheWideProvider),
			narrow.HashSize(), wide.HashSize()) {
			t.Errorf("%s left %s behind at %d bytes over a provider whose KDF.Nh is %d and at %d bytes over one whose KDF.Nh is %d; one of the two is a length written down rather than read",
				row.name, overTheNarrowProvider[at].name, len(overTheNarrowProvider[at].content),
				narrow.HashSize(), len(overTheWideProvider[at].content), wide.HashSize())
		}
		compared++
	}
	if compared != len(class) {
		t.Fatalf("%d of the %d methods handed a %s were compared across the two providers",
			compared, len(class), providerInterfaceName)
	}
}

// TestNoMethodHandedAProviderRetainsOrRewritesTheCallerBytes is
// TestEveryConstructionInThisPackageLeavesItsInputAlone over the other half of the partition,
// and it is the half where retention actually happens.
//
// A construction answers and is done with what it was handed. A method leaves state behind,
// and state outlives the array it was cut from. The joiner's confirmed transcript hash is the
// case: it is a field of a decoded GroupInfo, the caller still owns the message it decoded it
// out of and goes on reading later fields from that buffer, and a joiner that kept the slice
// holds a transcript that changes underneath it with no error path anywhere. The next commit
// is then chained from bytes no peer has, which is a permanent fork rather than an operation
// that failed.
//
// Both directions of sharing are read. The recorder's arrays carry a pattern in their spare
// capacity rather than zeros, so a method that appended a byte to save an allocation is
// visible; and every byte the receiver holds is compared against every byte of every argument,
// so state cut from the middle of a caller's buffer is as visible as state cut from its front.
func TestNoMethodHandedAProviderRetainsOrRewritesTheCallerBytes(t *testing.T) {
	class := providerDrivenMethodNamesTakingCallerBytes(t)
	crypto := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, constantReader{value: 0x35})
	compared := 0
	for _, row := range providerDrivenMethodRowsFor(t, "the retention gate", class) {
		recorder := &argumentRecorder{}
		held, err := row.call(t, crypto, recorder.take)
		if err != nil {
			t.Errorf("%s: %v", row.name, err)
			continue
		}
		if len(recorder.arrays) == 0 {
			t.Errorf("%s was handed nothing through the recorder, so this row observed nothing", row.name)
			continue
		}
		if changed := recorder.changed(); len(changed) != 0 {
			t.Errorf("%s wrote into the storage behind arguments %v of the %d it was handed",
				row.name, changed, len(recorder.arrays))
		}
		if len(held) == 0 {
			t.Errorf("%s left nothing behind, so this row observed nothing", row.name)
			continue
		}
		for _, value := range held {
			if len(value.content) == 0 {
				t.Errorf("%s left nothing behind in %s, so that value observed nothing", row.name, value.name)
				continue
			}
			if recorder.aliases(value.content) {
				t.Errorf("%s kept %s over the storage of one of the arrays it was handed; that array is its caller's and the state outlives the call",
					row.name, value.name)
			}
		}
		compared++
	}
	if compared != len(class) {
		t.Fatalf("%d of the %d methods handed a %s and a caller's array were run through the recorder",
			compared, len(class), providerInterfaceName)
	}
}

// TestEveryDeclarationTakingAProviderIsHeldByExactlyOneOfTheTwoClasses is what records the
// boundary the package level gates draw, so it cannot be widened or narrowed in silence.
//
// packageLevelFunctionsIn and providerConstructions each skip a declaration carrying a
// receiver. That skip is invisible from the gates reading them: they compare their tables
// against a class that never contained a method, find it matches, and report the clean run a
// complete gate reports. What says otherwise is this -- the whole of what the type checker
// reads as taking a provider, split by the same receiver test, with each half compared against
// the class the gates for that half actually run over.
//
// A declaration in neither half is one nothing holds. A declaration in both is a gate reading
// a class it was not built for. Either is a failure here rather than a coverage report that
// happens to be short.
func TestEveryDeclarationTakingAProviderIsHeldByExactlyOneOfTheTwoClasses(t *testing.T) {
	provider := providerInterfaceType(t)
	constructions := []string{}
	methods := []string{}
	for _, function := range declaredFunctionsOf(t, cryptoOwnRoot) {
		if len(function.takes(provider)) == 0 {
			continue
		}
		if function.method {
			methods = append(methods, function.name)
			continue
		}
		constructions = append(constructions, function.name)
	}
	if len(constructions) == 0 || len(methods) == 0 {
		t.Fatalf("the whole of what takes a %s reads as %d constructions and %d methods, so one of the two halves below is compared against nothing",
			providerInterfaceName, len(constructions), len(methods))
	}
	slices.Sort(constructions)
	slices.Sort(methods)
	if declared := packageLevelFunctionsTaking(t, providerInterfaceName); !slices.Equal(constructions, declared) {
		t.Errorf("the type checker reads %v as the constructions taking a %s and the package level scan the construction gates run over reads %v",
			constructions, providerInterfaceName, declared)
	}
	if held := providerDrivenMethodNames(t); !slices.Equal(methods, held) {
		t.Errorf("the type checker reads %v as the methods taking a %s and the gates in this file run over %v",
			methods, providerInterfaceName, held)
	}
	for _, name := range methods {
		if slices.Contains(constructions, name) {
			t.Errorf("%s reads as both a construction and a method, so one of the two gate families is running over a class it was not built for", name)
		}
	}
	// and the retention gate's narrower class is a subset of this one rather than a second
	// reading that could drift away from it
	for _, name := range providerDrivenMethodNamesTakingCallerBytes(t) {
		if !slices.Contains(methods, name) {
			t.Errorf("the retention gate runs over %s, which is not one of the methods taking a %s", name, providerInterfaceName)
		}
	}
	t.Logf("%d constructions and %d methods take a %s", len(constructions), len(methods), providerInterfaceName)
}

// TestTheByteSliceReadingAgreesWithTheSpellingBasedOne cross checks the two readings of
// "handed a caller's array" over the surface where both exist.
//
// The retention gate's class is read off the type checker; the construction gate's is read off
// the parse tree, matching []byte and the byte slice type names this package declares. Two
// readings of one property drift, and a reading that stopped matching shrinks the class it
// feeds while every gate over it goes on reporting a clean run. They share nothing but the
// package's source, so a filter that broke in either one is a disagreement here.
func TestTheByteSliceReadingAgreesWithTheSpellingBasedOne(t *testing.T) {
	typeChecked := []string{}
	for _, function := range declaredFunctionsOf(t, cryptoOwnRoot) {
		if function.method {
			continue
		}
		for i := 0; i < function.signature.Params().Len(); i++ {
			if isByteSliceType(function.signature.Params().At(i).Type()) {
				typeChecked = append(typeChecked, function.name)
				break
			}
		}
	}
	slices.Sort(typeChecked)
	if len(typeChecked) == 0 {
		t.Fatal("the type checked reading found no construction handed a caller's array, so this comparison holds for a filter that matches nothing")
	}
	if spelled := packageLevelFunctionsTakingCallerBytes(t); !slices.Equal(typeChecked, spelled) {
		t.Errorf("the type checked reading of the constructions handed a caller's array is %v and the spelling based one is %v",
			typeChecked, spelled)
	}
}
