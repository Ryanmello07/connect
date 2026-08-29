// The committed seed corpus for this plan's two decoders, and the deterministic regression net
// over it.
//
// Round-trip stability is the property that matters most here. MLS signs over serialized forms, so
// a decoder that accepts two encodings of one tree is a signature-bypass primitive rather than a
// leniency: encode(decode(x)) must be the canonical re-serialization, and decode(encode(decode(x)))
// must equal decode(x).
//
// WHY A CORPUS AT ALL. p1 measured it: uniform random bytes reach the round-trip property 14 times
// in 4096 -- 0.34 percent -- against the SIMPLEST structure in this tree, because the varint length
// prefix rejects them first, while a structured generator reaches it 4096 times in 4096. A target
// seeded only with random bytes spends its budget rediscovering the prefix. The structures here are
// far larger than the one that was measured -- a LeafNode has three source variants and a nested
// Credential, Capabilities, Lifetime and extensions vector; an UpdatePath is three levels of vector
// nesting over one of those -- so the fraction is smaller still.
//
// WHERE THE SEEDS LIVE, AND WHY NOT WHERE THE PLAN SAYS. The plan places them in
// mls/interop/testdata/corpus/<kind> for the validation plan's seedCorpus helper to read, on the
// belief that the validation plan owns targets named FuzzRatchetTreeDecode and FuzzUpdatePathDecode.
// It does not. That plan's nine Gate-4 targets are fuzzDecodeTarget over the five wire structures
// of its codec table -- extension, key package, mls message, proposal, welcome -- and its own
// TestFuzzTargetsCoverEveryKind asserts the count is nine and that each covers a table entry, so
// neither of these two can join it. Committing seeds under a target name no plan declares is
// exactly the defect p4's review found and fixed: 287 files no fuzz engine ever opened, every
// property stated over bytes nothing consumed, and a verification step that could not be run. The
// compose findings' own accounting agrees, listing "p5's two" among the Fuzz functions of this
// package outside p8's nine.
//
// So this file owns both halves, exactly as key_schedule_roundtrip_test.go does: the corpus lives
// under testdata/corpus/<Target> where addSeedCorpus looks, and the two targets that read it are
// declared at the foot of this file. TestEveryCommittedCorpusFolderIsReadByAFuzzTarget is what
// keeps that true.
//
// WHAT IS REUSED. Everything. The three properties p4's task 26 split apart -- the committed corpus
// IS the generated corpus, every committed seed re-encodes to its own bytes, every generated value
// is recovered by decoding its encoding -- plus the four derived coverage gates and the binary pin,
// are stated once over the seedCodecs table and these two codecs are entries in it. A second
// harness would be a second place for each of those properties to be weaker.
//
// WHAT HAD TO BE ADDED FOR THESE TWO. Two things, both because a ratchet tree is not shaped like a
// group context.
//
//   - RatchetTree's node array is UNEXPORTED, so the derived walks -- which fail rather than skip on
//     a field they cannot read, on purpose -- have nothing to walk. The codec entry supplies a
//     PROJECTION instead: the tree's own Get accessor, one *Node per index. It adds nothing the
//     container does not publish and it is not a second codec.
//   - A field can be single valued across the corpus because the CODEC pins it rather than because
//     the corpus is thin. Credential.CredentialType is the case: both halves of credential.go
//     refuse anything but CredentialTypeBasic, so no decodable seed can carry another value. The
//     variation gate now asks the codec rather than holding a list of exceptions -- see
//     seedFieldIsPinnedByTheCodec.
package mls

import (
	"bytes"
	"fmt"
	"math"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// The two target names. p8's own matrix in the compose findings already lists both, which is where
// these spellings come from rather than from a choice made here.
const (
	ratchetTreeSeedTarget = "FuzzRatchetTreeDecode"
	updatePathSeedTarget  = "FuzzUpdatePathDecode"
)

// ---------------------------------------------------------------------------
// the leaf axis
// ---------------------------------------------------------------------------

// seedRegistryVector is one registry's whole declared class as a wire vector, plus one code point
// that is NOT in it.
//
// Derived from the package's own constant declarations rather than listed, for rule 5's reason and
// for a specific one here: a LeafNode's Capabilities carry five registries, and a corpus that named
// the code points somebody remembered would leave the fuzzer blind to every decoder arm added
// afterwards. The unregistered 0xffff is there for the opposite reason, and it is p4's precedent:
// the codec does not decide policy, so an unregistered code point has to survive a round trip for
// validation to be able to refuse it by name.
func seedRegistryVector[T ~uint16](t *testing.T, typeName string) []T {
	t.Helper()
	values := sortedValues(registryConstantsOfType(t, typeName))
	out := make([]T, 0, len(values)+1)
	for _, value := range values {
		out = append(out, T(value))
	}
	return append(out, T(0xffff))
}

// seedEveryDeclaredCapability lists every code point of all five registries a Capabilities carries.
func seedEveryDeclaredCapability(t *testing.T) Capabilities {
	t.Helper()
	return Capabilities{
		Versions:     seedRegistryVector[ProtocolVersion](t, "ProtocolVersion"),
		CipherSuites: seedRegistryVector[CipherSuite](t, "CipherSuite"),
		Extensions:   seedRegistryVector[ExtensionType](t, "ExtensionType"),
		Proposals:    seedRegistryVector[ProposalType](t, "ProposalType"),
		Credentials:  seedRegistryVector[CredentialType](t, "CredentialType"),
	}
}

// seedExtensions is a deterministic extensions vector of the requested arity, cycling the declared
// extension types and the varint width boundaries through the bodies.
func seedExtensions(t *testing.T, count int) []Extension {
	t.Helper()
	if count == 0 {
		return nil
	}
	types := sortedValues(registryConstantsOfType(t, "ExtensionType"))
	lengths := seedOpaqueLengths()
	out := make([]Extension, 0, count)
	for index := 0; index < count; index += 1 {
		length := lengths[index%len(lengths)]
		var body []byte
		if length > 0 {
			body = repeatByte(byte(0x30+index), length)
		}
		out = append(out, Extension{
			ExtensionType: ExtensionType(types[index%len(types)]),
			ExtensionData: body,
		})
	}
	return out
}

// seedLeafVariant is one LeafNode the corpus carries, named so a failure says which shape moved.
type seedLeafVariant struct {
	name string
	leaf func(t *testing.T) *LeafNode
}

// seedNarrowLeafVariants are the leaf shapes the cross product below cycles through.
//
// The axes they cross, and why each is here rather than being left to the fuzzer:
//
//   - leaf_node_source, all three. It is a SUM TYPE the Go struct does not express: marshalCore
//     writes lifetime under key_package, nothing under update and parent_hash under commit, so the
//     three sources are three different wire grammars and a corpus holding one seeds a fuzzer that
//     has never seen the other two.
//   - the varint width boundaries of section 2.1.2 -- absent, one octet, the last length a one
//     octet prefix expresses, the first that needs two -- spread across the opaque fields, because
//     that prefix is what p1 measured random bytes failing at.
//   - the uint64 boundaries of the lifetime, which are the values a field narrowed to 32 bits or
//     read as signed would move. A leaf's lifetime is inside its signature, so a value that moves
//     is a member whose leaf verifies for a window nobody agreed to.
//   - vector arity, from zero up, for the five capability vectors and the extensions vector. Zero
//     and one agree with every reading of a length prefix; two is where a prefix counting BYTES
//     and one counting ELEMENTS part company.
//   - every declared code point of all five capability registries, derived.
//
// The wide leaf is NOT here: it carries a 16 KiB signature, and one seed per cross product entry
// carrying it would be megabytes of repository for a property of the prefix rather than of the
// field in front of it. It is added once, per corpus, below.
func seedNarrowLeafVariants() []seedLeafVariant {
	return []seedLeafVariant{
		{
			// every opaque absent and every vector empty. The smallest thing this grammar
			// accepts, which is the seed a fuzzer mutates outward from.
			name: "update/empty",
			leaf: func(t *testing.T) *LeafNode {
				return &LeafNode{
					Credential:     Credential{CredentialType: CredentialTypeBasic},
					LeafNodeSource: LeafNodeSourceUpdate,
				}
			},
		},
		{
			name: "update/every-registry",
			leaf: func(t *testing.T) *LeafNode {
				return &LeafNode{
					EncryptionKey:  repeatByte(0xa1, 32),
					SignatureKey:   repeatByte(0xa2, 32),
					Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: repeatByte(0xa3, 63)},
					Capabilities:   seedEveryDeclaredCapability(t),
					LeafNodeSource: LeafNodeSourceUpdate,
					Extensions:     seedExtensions(t, 1),
					Signature:      repeatByte(0xa4, 64),
				}
			},
		},
		{
			name: "keypackage/lifetime-low",
			leaf: func(t *testing.T) *LeafNode {
				return &LeafNode{
					EncryptionKey: repeatByte(0xb1, 1),
					SignatureKey:  repeatByte(0xb2, 63),
					Credential:    Credential{CredentialType: CredentialTypeBasic, Identity: repeatByte(0xb3, 1)},
					Capabilities: Capabilities{
						Versions: []ProtocolVersion{ProtocolVersionMls10},
					},
					LeafNodeSource: LeafNodeSourceKeyPackage,
					Lifetime:       Lifetime{NotBefore: 0, NotAfter: 1},
					Signature:      repeatByte(0xb4, 1),
				}
			},
		},
		{
			name: "keypackage/lifetime-uint32-boundary",
			leaf: func(t *testing.T) *LeafNode {
				return &LeafNode{
					EncryptionKey: repeatByte(0xc1, 64),
					SignatureKey:  repeatByte(0xc2, 64),
					Credential:    Credential{CredentialType: CredentialTypeBasic, Identity: repeatByte(0xc3, 64)},
					Capabilities: Capabilities{
						Versions:     []ProtocolVersion{ProtocolVersionMls10, 0xffff},
						CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20Sha256Ed25519},
					},
					LeafNodeSource: LeafNodeSourceKeyPackage,
					Lifetime:       Lifetime{NotBefore: math.MaxUint32, NotAfter: uint64(math.MaxUint32) + 1},
					Extensions:     seedExtensions(t, 2),
					Signature:      repeatByte(0xc4, 63),
				}
			},
		},
		{
			name: "keypackage/lifetime-sign-bit",
			leaf: func(t *testing.T) *LeafNode {
				return &LeafNode{
					EncryptionKey:  repeatByte(0xd1, 63),
					SignatureKey:   repeatByte(0xd2, 1),
					Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: repeatByte(0xd3, 32)},
					LeafNodeSource: LeafNodeSourceKeyPackage,
					Lifetime:       Lifetime{NotBefore: 1 << 63, NotAfter: math.MaxUint64},
					Extensions:     seedExtensions(t, 3),
					Signature:      repeatByte(0xd4, 32),
				}
			},
		},
		{
			name: "commit/parent-hash-one-octet",
			leaf: func(t *testing.T) *LeafNode {
				return &LeafNode{
					EncryptionKey: repeatByte(0xe1, 32),
					SignatureKey:  repeatByte(0xe2, 32),
					Credential:    Credential{CredentialType: CredentialTypeBasic},
					Capabilities: Capabilities{
						Proposals:   []ProposalType{ProposalTypeReserved, ProposalTypeAdd},
						Credentials: []CredentialType{CredentialTypeBasic},
					},
					LeafNodeSource: LeafNodeSourceCommit,
					ParentHash:     repeatByte(0xe3, 1),
					Signature:      repeatByte(0xe4, 63),
				}
			},
		},
		{
			name: "commit/parent-hash-digest",
			leaf: func(t *testing.T) *LeafNode {
				return &LeafNode{
					EncryptionKey:  repeatByte(0xf1, 1),
					SignatureKey:   repeatByte(0xf2, 64),
					Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: repeatByte(0xf3, 63)},
					Capabilities:   Capabilities{Extensions: []ExtensionType{ExtensionTypeRatchetTree}},
					LeafNodeSource: LeafNodeSourceCommit,
					ParentHash:     repeatByte(0xf4, 32),
					Extensions:     seedExtensions(t, 4),
					Signature:      repeatByte(0xf5, 64),
				}
			},
		},
	}
}

// seedWideLeaf carries the first length whose varint prefix needs four octets, which is
// seedWideOpaqueLength and is the axis key_schedule_roundtrip_test.go already states the cost of.
func seedWideLeaf(t *testing.T) *LeafNode {
	t.Helper()
	return &LeafNode{
		EncryptionKey:  repeatByte(0x11, 32),
		SignatureKey:   repeatByte(0x12, 32),
		Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: repeatByte(0x13, 1)},
		LeafNodeSource: LeafNodeSourceCommit,
		ParentHash:     repeatByte(0x14, 63),
		Signature:      repeatByte(0x15, seedWideOpaqueLength),
	}
}

// ---------------------------------------------------------------------------
// the parent axis
// ---------------------------------------------------------------------------

// seedParentVariants cross the parent node's three fields: the encryption key and the parent hash
// over the varint width boundaries, and unmerged_leaves over its arity.
//
// unmerged_leaves is the field with the most to say. The codec refuses a vector that is not
// STRICTLY ascending on both sides, so a corpus carrying only the empty one seeds a fuzzer that has
// never seen the ordering rule hold, let alone break; and the values are LEAF indices carried as
// uint32, which section 7.9.2 later equates against a resolution of NODE indices.
func seedParentVariants() []*ParentNode {
	return []*ParentNode{
		{},
		{
			EncryptionKey:  repeatByte(0x21, 32),
			ParentHash:     repeatByte(0x22, 32),
			UnmergedLeaves: []LeafIndex{0},
		},
		{
			EncryptionKey:  repeatByte(0x23, 1),
			ParentHash:     repeatByte(0x24, 63),
			UnmergedLeaves: []LeafIndex{0, 1, 3},
		},
		{
			EncryptionKey:  repeatByte(0x25, 64),
			ParentHash:     repeatByte(0x26, 64),
			UnmergedLeaves: []LeafIndex{2, 5},
		},
	}
}

// ---------------------------------------------------------------------------
// the tree shapes
// ---------------------------------------------------------------------------

// seedTreeShapes are the node arrays the corpus carries, one character per node index: L a leaf, P
// a parent, and a full stop a blank.
//
// Written as strings so the SHAPE is legible and so the parity rule -- leaves at even indices,
// parents at odd -- can be checked against the tree math rather than trusted, which
// seedRatchetTreeFromShape does on every build. Every width here is 2n-1 for a power-of-two n,
// because readNodeArray refuses anything else.
//
// The shapes cross what a decoder branches on: the width, whether the first leaf is blank, whether
// a parent is blank, whether the array ENDS in a blank -- that last one is ValSem300, the rule that
// the encoder strips trailing blanks and the decoder refuses an array that carries one, so the
// "LPLPLP." row is the only one whose committed bytes are shorter than its node width.
func seedTreeShapes() []string {
	return []string{
		"L",
		"LPL",
		".PL",
		"L.L",
		"LPLPLPL",
		"L..P..L",
		"LPLPLP.",
		"LPLPLPLPLPLPLPL",
		"L.L.L.LPL.L.L.L",
		"..LPL...LPLPLPL",
	}
}

// seedRatchetTreeFromShape builds one tree, taking its leaves and parents from the variant cycles
// starting at offset.
//
// The parity of every position is asserted against NodeIndex.IsLeaf rather than against the string,
// because the string is what this function is being told and the arithmetic is what the decoder
// will judge it by. A shape with a leaf at an odd index encodes fine and is refused by
// readNodeArray, which would show up as an unexplained corpus that does not decode.
func seedRatchetTreeFromShape(t *testing.T, shape string, offset int, leaves []seedLeafVariant) *RatchetTree {
	t.Helper()
	parents := seedParentVariants()
	nodes := make([]*Node, len(shape))
	leafSlot, parentSlot := 0, 0
	for index, token := range shape {
		x := NodeIndex(index)
		switch token {
		case 'L':
			if !x.IsLeaf() {
				t.Fatalf("shape %q puts a leaf at node %d, which is a parent position", shape, index)
			}
			nodes[index] = &Node{
				NodeType: NodeTypeLeaf,
				Leaf:     leaves[(offset+leafSlot)%len(leaves)].leaf(t),
			}
			leafSlot += 1
		case 'P':
			if x.IsLeaf() {
				t.Fatalf("shape %q puts a parent at node %d, which is a leaf position", shape, index)
			}
			nodes[index] = &Node{
				NodeType: NodeTypeParent,
				Parent:   parents[(offset+parentSlot)%len(parents)].Clone(),
			}
			parentSlot += 1
		case '.':
		default:
			t.Fatalf("shape %q holds %q, which is not one of L, P or .", shape, token)
		}
	}
	if _, err := LeafCountFromNodeWidth(uint32(len(nodes))); err != nil {
		t.Fatalf("shape %q is %d nodes wide, which is not 2n-1 for any n: %v", shape, len(nodes), err)
	}
	return &RatchetTree{nodes: nodes}
}

// seedRatchetTrees is the cross product: every shape against every rotation of the leaf and parent
// variant cycles, plus the one wide seed.
func seedRatchetTrees(t *testing.T) []*RatchetTree {
	t.Helper()
	leaves := seedNarrowLeafVariants()
	trees := []*RatchetTree{}
	for _, shape := range seedTreeShapes() {
		for offset := 0; offset < len(leaves); offset += 1 {
			trees = append(trees, seedRatchetTreeFromShape(t, shape, offset, leaves))
		}
	}
	// the four octet varint prefix, once. The tree around it is the smallest one that still holds a
	// parent, so the seed is the wide field and almost nothing else.
	wide := &RatchetTree{nodes: []*Node{
		{NodeType: NodeTypeLeaf, Leaf: seedWideLeaf(t)},
		{NodeType: NodeTypeParent, Parent: seedParentVariants()[1].Clone()},
		{NodeType: NodeTypeLeaf, Leaf: seedNarrowLeafVariants()[0].leaf(t)},
	}}
	return append(trees, wide)
}

// ---------------------------------------------------------------------------
// the update path shapes
// ---------------------------------------------------------------------------

// seedUpdatePathShapes are the ciphertext counts per path node: the outer vector's arity is the
// length of the row, and each entry is the arity of that node's own ciphertext vector.
//
// Three levels of nesting is the whole difficulty of this structure, and it is why the rows below
// are not all the same width: an UpdatePath holds a vector of nodes, each node holds a vector of
// HPKE ciphertexts, and each ciphertext holds two opaques. A decoder that read the inner arity as a
// byte count, or the outer one as an element count, agrees with itself on every row of arity zero
// and one and parts company at the first row that has two of anything.
func seedUpdatePathShapes() [][]int {
	return [][]int{
		{},
		{0},
		{1},
		{0, 1, 2},
		{2, 3},
		{1, 1, 1, 1},
	}
}

// seedUpdatePathFromShape builds one path, cycling the opaque lengths through the ciphertexts so
// the varint width boundaries appear at every level of the nesting rather than only at the top.
func seedUpdatePathFromShape(t *testing.T, shape []int, offset int, leaves []seedLeafVariant) *UpdatePath {
	t.Helper()
	lengths := seedOpaqueLengths()
	path := &UpdatePath{LeafNode: *leaves[offset%len(leaves)].leaf(t)}
	for index, ciphertexts := range shape {
		node := UpdatePathNode{}
		if keyLength := lengths[(offset+index)%len(lengths)]; keyLength > 0 {
			node.EncryptionKey = repeatByte(byte(0x40+index), keyLength)
		}
		for which := 0; which < ciphertexts; which += 1 {
			kemLength := lengths[(offset+index+which)%len(lengths)]
			ciphertextLength := lengths[(offset+index+which+1)%len(lengths)]
			one := HpkeCiphertext{}
			if kemLength > 0 {
				one.KemOutput = repeatByte(byte(0x50+which), kemLength)
			}
			if ciphertextLength > 0 {
				one.Ciphertext = repeatByte(byte(0x60+which), ciphertextLength)
			}
			node.EncryptedPathSecret = append(node.EncryptedPathSecret, one)
		}
		path.Nodes = append(path.Nodes, node)
	}
	return path
}

func seedUpdatePaths(t *testing.T) []*UpdatePath {
	t.Helper()
	leaves := seedNarrowLeafVariants()
	paths := []*UpdatePath{}
	for _, shape := range seedUpdatePathShapes() {
		for offset := 0; offset < len(leaves); offset += 1 {
			paths = append(paths, seedUpdatePathFromShape(t, shape, offset, leaves))
		}
	}
	// the four octet varint prefix, once, on the innermost field: a ciphertext rather than the
	// leaf's signature, so the wide length is reached through all three levels of the nesting.
	wide := &UpdatePath{
		LeafNode: *seedNarrowLeafVariants()[0].leaf(t),
		Nodes: []UpdatePathNode{{
			EncryptionKey: repeatByte(0x71, 32),
			EncryptedPathSecret: []HpkeCiphertext{{
				KemOutput:  repeatByte(0x72, 32),
				Ciphertext: repeatByte(0x73, seedWideOpaqueLength),
			}},
		}},
	}
	return append(paths, wide)
}

// ---------------------------------------------------------------------------
// the two codec table entries
// ---------------------------------------------------------------------------

// ratchetTreeNodes is the PROJECTION the derived walks read a tree through: one *Node per index,
// through the container's own accessor, a typed nil for a blank.
//
// It exists because RatchetTree.nodes is unexported and the walks in
// key_schedule_roundtrip_test.go fail rather than skip on a field they cannot read -- which is the
// right behaviour, since a field a comparison cannot read is a field it reports equal whatever it
// holds. What this hands them is exactly what the container publishes and nothing more: Get is the
// same accessor every other reader of a tree uses, and it answers nil for a blank and for an index
// past the end alike.
//
// The values are the tree's OWN nodes rather than copies, which matters for
// seedFieldIsPinnedByTheCodec: that probe perturbs a field of a decoded value and re-encodes it, so
// it needs the walk to reach the storage the encoder will read.
func ratchetTreeNodes(value any) []any {
	tree := value.(*RatchetTree)
	out := make([]any, 0, tree.NodeWidth())
	for x := uint32(0); x < tree.NodeWidth(); x += 1 {
		node := tree.Get(NodeIndex(x))
		out = append(out, node)
	}
	return out
}

// updatePathItself is the identity projection. It is spelled out rather than left nil so that the
// probe below reaches an UpdatePath through the same code path it reaches a tree through, and a
// change to one is a change to both.
func updatePathItself(value any) []any {
	return []any{value.(*UpdatePath)}
}

func describeRatchetTree(tree *RatchetTree) string {
	if tree == nil {
		return "<nil tree>"
	}
	leaves, parents, blanks := 0, 0, 0
	for x := uint32(0); x < tree.NodeWidth(); x += 1 {
		node := tree.Get(NodeIndex(x))
		switch {
		case node == nil:
			blanks += 1
		case node.Leaf != nil:
			leaves += 1
		default:
			parents += 1
		}
	}
	return fmt.Sprintf("tree of %d nodes: %d leaves, %d parents, %d blank",
		tree.NodeWidth(), leaves, parents, blanks)
}

// describeUpdatePath is treekem_test.go, and it is reused rather than restated: that one spells all
// three levels of the nesting out, which is what a corpus failure has to say.

// treeSeedCodecs is this plan's half of the shared seedCodecs table.
//
// The ratchet tree entry runs at syntax.MaxRatchetTreeLength on BOTH halves, which is not an
// optimisation and is stated in syntax.CheckRoundTripLimit's own comment: a structure that decodes
// only under the raised bound does not decode under the default one, and CheckRoundTrip's contract
// for an input that does not decode is to return nil. A ratchet tree target built on the default
// bound would be not merely mostly vacuous but entirely so, and indistinguishable from one that
// found nothing wrong.
func treeSeedCodecs() []seedCodec {
	return []seedCodec{
		{
			target:    ratchetTreeSeedTarget,
			structure: func() any { return &Node{} },
			project:   ratchetTreeNodes,
			values: func(t *testing.T) []any {
				values := []any{}
				for _, value := range seedRatchetTrees(t) {
					values = append(values, value)
				}
				return values
			},
			decode: func(bs []byte) (any, error) {
				return UnmarshalRatchetTree(bs)
			},
			encode: func(value any) ([]byte, error) { return marshalRatchetTree(value.(*RatchetTree)) },
			checkRoundTrip: func(bs []byte) error {
				return syntax.CheckRoundTripLimit[RatchetTree, *RatchetTree](bs, syntax.MaxRatchetTreeLength)
			},
			describe: func(value any) string { return describeRatchetTree(value.(*RatchetTree)) },
		},
		{
			target:    updatePathSeedTarget,
			structure: func() any { return &UpdatePath{} },
			project:   updatePathItself,
			values: func(t *testing.T) []any {
				values := []any{}
				for _, value := range seedUpdatePaths(t) {
					values = append(values, value)
				}
				return values
			},
			decode: func(bs []byte) (any, error) {
				parsed := &UpdatePath{}
				return parsed, syntax.Unmarshal(bs, parsed)
			},
			encode:         func(value any) ([]byte, error) { return syntax.Marshal(value.(*UpdatePath)) },
			checkRoundTrip: syntax.CheckRoundTrip[UpdatePath, *UpdatePath],
			describe:       func(value any) string { return describeUpdatePath(value.(*UpdatePath)) },
		},
	}
}

// ---------------------------------------------------------------------------
// the two properties the plan names
// ---------------------------------------------------------------------------

// TestRatchetTreeDecodeIsRoundTripStable is round-trip stability over the committed ratchet tree
// corpus, deterministically and in every go test run rather than only under -fuzz.
//
// It states the plan's own two claims -- the canonical re-encoding decodes, and encoding it again
// gives the same bytes -- and adds the one the plan's version could not make, which is a count. A
// loop whose body never ran reports exactly what a loop that checked every seed reports, and on
// this project that is not hypothetical: three CheckRoundTrip tests once passed against a helper
// that evaluated the comparison, discarded the result and returned nil. So the decodes are counted
// and zero is fatal.
//
// It overlaps TestEverySeedInTheCommittedCorpusReEncodesToItsOwnBytes deliberately and adds two
// things that property does not say: that the tree's WIDTH survives the round trip, which is the
// one field of a ratchet tree that is not written down anywhere on the wire -- readNodeArray
// derives it by extension from the entry count -- and that the SECOND encoding is stable, which is
// the difference between "encode of decode is canonical" and "decode is a function".
func TestRatchetTreeDecodeIsRoundTripStable(t *testing.T) {
	names, onDisk := readSeedCorpus(t, ratchetTreeSeedTarget)
	decoded := 0
	for _, name := range names {
		data := onDisk[name]
		tree, err := UnmarshalRatchetTree(data)
		if err != nil {
			t.Errorf("%s: the corpus holds only accepted inputs: %v", name, err)
			continue
		}
		decoded += 1
		encoded, err := marshalRatchetTree(tree)
		if err != nil {
			t.Errorf("%s: a decoded tree failed to re-encode: %v", name, err)
			continue
		}
		if !bytes.Equal(encoded, data) {
			t.Errorf("%s: the decoder accepted a non-canonical encoding of %s:\n     got %x\ncommitted %x",
				name, describeRatchetTree(tree), encoded, data)
			continue
		}
		again, err := UnmarshalRatchetTree(encoded)
		if err != nil {
			t.Errorf("%s: the canonical re-encoding failed to decode: %v", name, err)
			continue
		}
		reencoded, err := marshalRatchetTree(again)
		if err != nil {
			t.Errorf("%s: re-encode: %v", name, err)
			continue
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Errorf("%s: encoding is not stable across a second round trip", name)
			continue
		}
		if again.NodeWidth() != tree.NodeWidth() {
			t.Errorf("%s: node width changed across a round trip: %d then %d",
				name, tree.NodeWidth(), again.NodeWidth())
		}
	}
	if decoded == 0 {
		t.Fatalf("not one of the %d committed seeds decoded, so this property reached nothing; a corpus of bytes no decoder accepts makes every claim over it trivially true",
			len(names))
	}
	if decoded != len(names) {
		t.Errorf("%d of %d committed seeds decoded", decoded, len(names))
	}
	t.Logf("%d ratchet tree seeds are round trip stable", decoded)
}

// TestUpdatePathDecodeIsRoundTripStable is the same property over the update path corpus, plus the
// node count, which is the arity the three levels of nesting make it possible to lose one level
// down without changing the length of anything.
func TestUpdatePathDecodeIsRoundTripStable(t *testing.T) {
	names, onDisk := readSeedCorpus(t, updatePathSeedTarget)
	decoded := 0
	for _, name := range names {
		data := onDisk[name]
		path := &UpdatePath{}
		if err := syntax.Unmarshal(data, path); err != nil {
			t.Errorf("%s: the corpus holds only accepted inputs: %v", name, err)
			continue
		}
		decoded += 1
		encoded, err := syntax.Marshal(path)
		if err != nil {
			t.Errorf("%s: a decoded update path failed to re-encode: %v", name, err)
			continue
		}
		if !bytes.Equal(encoded, data) {
			t.Errorf("%s: the decoder accepted a non-canonical encoding of %s:\n     got %s\ncommitted %s",
				name, describeUpdatePath(path), HexOf(encoded), HexOf(data))
			continue
		}
		again := &UpdatePath{}
		if err := syntax.Unmarshal(encoded, again); err != nil {
			t.Errorf("%s: the canonical re-encoding failed to decode: %v", name, err)
			continue
		}
		reencoded, err := syntax.Marshal(again)
		if err != nil {
			t.Errorf("%s: re-encode: %v", name, err)
			continue
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Errorf("%s: encoding is not stable across a second round trip", name)
			continue
		}
		if len(again.Nodes) != len(path.Nodes) {
			t.Errorf("%s: node count changed across a round trip: %d then %d",
				name, len(path.Nodes), len(again.Nodes))
		}
		for index := range path.Nodes {
			if len(again.Nodes[index].EncryptedPathSecret) != len(path.Nodes[index].EncryptedPathSecret) {
				t.Errorf("%s: node %d's ciphertext count changed across a round trip: %d then %d",
					name, index, len(path.Nodes[index].EncryptedPathSecret),
					len(again.Nodes[index].EncryptedPathSecret))
			}
		}
	}
	if decoded == 0 {
		t.Fatalf("not one of the %d committed seeds decoded, so this property reached nothing", len(names))
	}
	if decoded != len(names) {
		t.Errorf("%d of %d committed seeds decoded", decoded, len(names))
	}
	t.Logf("%d update path seeds are round trip stable", decoded)
}

// ---------------------------------------------------------------------------
// the targets that read these two corpora
// ---------------------------------------------------------------------------

// FuzzRatchetTreeDecode is Gate 4 properties 1 and 2 on the section 12.4.3.3 ratchet_tree body in
// their randomized form: no panic on adversarial input, and an encoding that decodes must re-encode
// to the bytes it came from.
//
// Through CheckRoundTripLimit at MaxRatchetTreeLength rather than the default entry point, and that
// is the whole difference between this target and a vacuous one -- see treeSeedCodecs above.
func FuzzRatchetTreeDecode(f *testing.F) {
	addSeedCorpus(f, ratchetTreeSeedTarget)
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if err := syntax.CheckRoundTripLimit[RatchetTree, *RatchetTree](encoded,
			syntax.MaxRatchetTreeLength); err != nil {
			t.Fatalf("%d octets %x: %v", len(encoded), encoded, err)
		}
	})
}

// FuzzUpdatePathDecode is the same two properties on the section 7.6 UpdatePath. A separate target
// rather than a second case of one, for the reason p4 states: the fuzzing engine keeps its coverage
// feedback and its found corpus per target, so one target over two grammars spends half its budget
// on each while reporting one.
func FuzzUpdatePathDecode(f *testing.F) {
	addSeedCorpus(f, updatePathSeedTarget)
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if err := syntax.CheckRoundTrip[UpdatePath, *UpdatePath](encoded); err != nil {
			t.Fatalf("%d octets %x: %v", len(encoded), encoded, err)
		}
	})
}
