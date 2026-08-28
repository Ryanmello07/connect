// The registry enums, the extensions<V> lookup, and the two structures that decide whether a
// member may join a group.
//
// Capabilities and RequiredCapabilities are a validation surface rather than a data structure,
// and the defect they attract is a comparison that is permissive in the wrong direction. A
// required_capabilities check that accepts a member missing a required extension admits a
// member who cannot process the group's messages; one that rejects a member who has everything
// is a group nobody can join. Neither reads as an error where the mistake is, and neither is
// visible to a round trip property: both directions encode and decode perfectly.
//
// So the predicates below are stated in BOTH directions over a class derived from the types
// themselves -- every registry RequiredCapabilities carries, every code point the package
// declares for it, a member with it and a member without it -- rather than over a table of
// cases somebody picked. On this project a hand written class has understated the real one
// fourteen times.
//
// The codec half is held to another implementation's bytes rather than to its own. A golden
// captured from the encoder under test pins nothing at all: five vectors of uint16 in the
// wrong order round trip perfectly, agree with themselves, and disagree with every peer. The
// goldens here are hand derived from RFC 9420 section 7.2 and section 11.1 and then checked
// against the mlswg vectors, which are bytes this package had no part in producing.
package mls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// ---------------------------------------------------------------------------
// the hand derived goldens
// ---------------------------------------------------------------------------

// repeatUint16 is repeatByte's two octet twin: count copies of one code point, big endian, as
// the bytes a registry vector's body is made of.
func repeatUint16(value uint16, count int) []byte {
	out := make([]byte, 0, 2*count)
	for range count {
		out = append(out, byte(value>>8), byte(value))
	}
	return out
}

// handDerivedUpstreamCapabilitiesGolden is RFC 9420 section 7.2 written out by hand:
//
//	versions<V>       01 code point   -> 02 0001
//	cipher_suites<V>  06 code points  -> 0c 000100020003000400050006
//	extensions<V>     empty           -> 00
//	proposals<V>      empty           -> 00
//	credentials<V>    02 code points  -> 04 00010002
//
// 3 + 13 + 1 + 1 + 5 = 23 octets. Each prefix is the MLS varint counting BYTES and not
// elements, which for a fixed width element is the one arithmetic in this encoding that can be
// wrong while every symmetry property still holds.
//
// It is the capabilities of a leaf in the mlswg ratchet_tree vectors, so
// TestCapabilitiesHandDerivedGoldenMatchesTheUpstreamVectors can check this derivation against
// bytes written by another implementation before anything is asserted against it.
func handDerivedUpstreamCapabilitiesGolden() []byte {
	return joinBytes(
		[]byte{0x02}, []byte{0x00, 0x01},
		[]byte{0x0c}, []byte{0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06},
		[]byte{0x00},
		[]byte{0x00},
		[]byte{0x04}, []byte{0x00, 0x01, 0x00, 0x02},
	)
}

// upstreamCapabilitiesGoldenValue is the structure those bytes describe.
func upstreamCapabilitiesGoldenValue() *Capabilities {
	return &Capabilities{
		Versions: []ProtocolVersion{ProtocolVersionMls10},
		CipherSuites: []CipherSuite{
			CipherSuite(0x0001), CipherSuite(0x0002), CipherSuite(0x0003),
			CipherSuite(0x0004), CipherSuite(0x0005), CipherSuite(0x0006),
		},
		Extensions:  []ExtensionType{},
		Proposals:   []ProposalType{},
		Credentials: []CredentialType{CredentialTypeBasic, CredentialType(0x0002)},
	}
}

// handDerivedProfileCapabilitiesGolden pins what the published vectors cannot: an empty
// leading vector, this profile's own 0xF00x extension code points, a proposals vector holding
// a code point no registry entry of this package declares, and an extensions vector exactly at
// the width where the MLS varint stops being one octet.
//
//	versions<V>       01 code point   -> 02 0001
//	cipher_suites<V>  empty           -> 00
//	extensions<V>     32 code points  -> 4040 then 64 octets of f002
//	proposals<V>      02 code points  -> 04 00070008
//	credentials<V>    01 code point   -> 02 0001
//
// 3 + 1 + 66 + 5 + 3 = 78 octets. The 64 octet body is the point of the third line: 63 is the
// last length a one octet prefix expresses and 64 is the first that needs two, so an encoder
// writing the prefix as a bare uint8 produces 63 correct vectors and then a wrong one.
func handDerivedProfileCapabilitiesGolden() []byte {
	return joinBytes(
		[]byte{0x02}, []byte{0x00, 0x01},
		[]byte{0x00},
		[]byte{0x40, 0x40}, repeatUint16(0xf002, 32),
		[]byte{0x04}, []byte{0x00, 0x07, 0x00, 0x08},
		[]byte{0x02}, []byte{0x00, 0x01},
	)
}

// profileCapabilitiesGoldenValue is the structure those bytes describe.
func profileCapabilitiesGoldenValue() *Capabilities {
	extensions := make([]ExtensionType, 0, 32)
	for range 32 {
		extensions = append(extensions, ExtensionTypeUrmessageLeafKeys)
	}
	return &Capabilities{
		Versions:     []ProtocolVersion{ProtocolVersionMls10},
		CipherSuites: nil,
		Extensions:   extensions,
		// 0x0008 is not a code point this package declares, and it is here on purpose: a
		// peer's capabilities are attacker chosen bytes and an unregistered value has to
		// survive being read and written back, or the signature over the leaf carrying it
		// stops verifying at this implementation and nowhere else.
		Proposals:   []ProposalType{ProposalTypeGroupContextExtensions, ProposalType(0x0008)},
		Credentials: []CredentialType{CredentialTypeBasic},
	}
}

// handDerivedUpstreamRequiredCapabilitiesGolden is RFC 9420 section 11.1 written out by hand
// for the empty requirement: three vectors, each a single zero length prefix.
//
//	extension_types<V>   empty -> 00
//	proposal_types<V>    empty -> 00
//	credential_types<V>  empty -> 00
//
// Three octets, and the count of them is the assertion: a structure encoded with two vectors
// or four is a required_capabilities extension body every peer parses differently, and this
// exact encoding is what the mlswg group_info vectors carry.
func handDerivedUpstreamRequiredCapabilitiesGolden() []byte {
	return []byte{0x00, 0x00, 0x00}
}

// handDerivedProfileRequiredCapabilitiesGolden is the non empty form, which no published
// vector carries:
//
//	extension_types<V>   02 code points -> 04 f001f002
//	proposal_types<V>    empty          -> 00
//	credential_types<V>  01 code point  -> 02 0001
//
// 5 + 1 + 3 = 9 octets. The empty vector in the MIDDLE is what this adds over the one above:
// an encoder that wrote the three vectors in the wrong order still produces three prefixes,
// and only a case where the three differ can tell the orders apart.
func handDerivedProfileRequiredCapabilitiesGolden() []byte {
	return joinBytes(
		[]byte{0x04}, []byte{0xf0, 0x01, 0xf0, 0x02},
		[]byte{0x00},
		[]byte{0x02}, []byte{0x00, 0x01},
	)
}

// profileRequiredCapabilitiesGoldenValue is the structure those bytes describe.
func profileRequiredCapabilitiesGoldenValue() *RequiredCapabilities {
	return &RequiredCapabilities{
		ExtensionTypes:  []ExtensionType{ExtensionTypeUrmessageGroupPolicy, ExtensionTypeUrmessageLeafKeys},
		ProposalTypes:   nil,
		CredentialTypes: []CredentialType{CredentialTypeBasic},
	}
}

// handDerivedRequiredCapabilitiesExtensionGolden is one Extension entry, section 6.3.1: the
// uint16 registry code point then the opaque body.
//
//	extension_type            -> 0003
//	extension_data<V>, 3 body -> 03 000000
//
// Six octets, and it is byte for byte the required_capabilities entry the mlswg group_info
// vectors carry, so the entry framing is pinned to another implementation rather than to this
// file's arithmetic.
func handDerivedRequiredCapabilitiesExtensionGolden() []byte {
	return joinBytes([]byte{0x00, 0x03}, []byte{0x03}, []byte{0x00, 0x00, 0x00})
}

// handDerivedLongExtensionGolden is an entry whose body crosses the varint width boundary:
// type 0xf002, then a 64 octet body, which needs the two octet prefix 0x4040. 2 + 2 + 64 = 68.
func handDerivedLongExtensionGolden() []byte {
	return joinBytes([]byte{0xf0, 0x02}, []byte{0x40, 0x40}, repeatByte(0x5a, 64))
}

// handDerivedExtensionsVectorGolden is the extensions<V> vector holding the entry above: the
// vector's own byte count, then the entry. 01 + 06 = 07 octets, and it is what the mlswg
// group_info vectors carry in the group context's last field.
func handDerivedExtensionsVectorGolden() []byte {
	return joinBytes([]byte{0x06}, handDerivedRequiredCapabilitiesExtensionGolden())
}

// ---------------------------------------------------------------------------
// the upstream corpus
// ---------------------------------------------------------------------------

// vectorFilePaths is every mlswg vector file, derived from the directory rather than listed.
// A family added to testdata enters the scans below in the commit that vendors it.
func vectorFilePaths(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "vectors", "*.json"))
	if err != nil {
		t.Fatalf("list the vector files: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no vector file was found, so every upstream property below compares against nothing")
	}
	slices.Sort(paths)
	return paths
}

// hexStringsIn walks a decoded JSON document and yields every string in it that is valid hex,
// at any depth. The mlswg families nest differently from each other -- messages.json is a flat
// list of objects, the passive client families carry arrays of epochs -- and a walk over the
// shape is what lets one scan read all of them without a per family reader.
func hexStringsIn(value any, out *[][]byte) {
	switch typed := value.(type) {
	case string:
		if len(typed) == 0 || len(typed)%2 != 0 {
			return
		}
		decoded, err := hex.DecodeString(typed)
		if err != nil {
			return
		}
		*out = append(*out, decoded)
	case []any:
		for _, item := range typed {
			hexStringsIn(item, out)
		}
	case map[string]any:
		for _, name := range slices.Sorted(maps.Keys(typed)) {
			hexStringsIn(typed[name], out)
		}
	}
}

// upstreamLeafCapabilities is every distinct Capabilities encoding the vendored mlswg vectors
// contain, keyed by its hex.
//
// The extraction is written here rather than taken from this package because this package has
// no LeafNode yet -- task 5 adds it -- and because a golden read back through the code under
// test is not a golden. What it uses from the package is syntax.Reader, which is the layer
// below and has its own published vectors, and the capabilities are lifted out as a BYTE RANGE
// rather than decoded, so what the assertions compare is upstream's octets against this
// encoder's.
//
// Every string in every file is tried, and the ones that are not ratchet trees or leaf nodes
// simply fail to parse. Selecting by field name would be a list of upstream's spellings, which
// is the enumeration rule 5 objects to; strict parsing -- exact region consumption, a
// recognised credential type, a recognised leaf node source -- is what separates a tree from a
// blob without one.
func upstreamLeafCapabilities(t *testing.T) map[string][]byte {
	t.Helper()
	found := map[string][]byte{}
	leaves := 0
	for _, path := range vectorFilePaths(t) {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var document any
		if err := json.Unmarshal(body, &document); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		blobs := [][]byte{}
		hexStringsIn(document, &blobs)
		for _, blob := range blobs {
			for _, capabilities := range leafCapabilitiesOfRatchetTree(blob) {
				found[hex.EncodeToString(capabilities)] = capabilities
				leaves++
			}
			if capabilities, ok := leafCapabilitiesOfLeafNode(blob); ok {
				found[hex.EncodeToString(capabilities)] = capabilities
				leaves++
			}
		}
	}
	if leaves == 0 {
		t.Fatal("no leaf node was read out of the vendored vectors, so every upstream comparison below is against an empty set")
	}
	t.Logf("%d upstream leaf nodes read, %d distinct capabilities encodings", leaves, len(found))
	return found
}

// leafCapabilitiesOfRatchetTree reads blob as a ratchet_tree extension body -- optional<Node>
// nodes<V> -- and returns the capabilities byte range of every leaf in it. A blob that is not
// one yields nothing rather than an error, because every string in every vector file is tried.
func leafCapabilitiesOfRatchetTree(blob []byte) [][]byte {
	outer := syntax.NewReader(blob)
	nodes, err := outer.ReadOpaque()
	if err != nil || outer.Done() != nil {
		return nil
	}
	r := syntax.NewReader(nodes)
	found := [][]byte{}
	for !r.Empty() {
		present, err := r.ReadUint8()
		if err != nil || present > 1 {
			return nil
		}
		if present == 0 {
			continue
		}
		nodeType, err := r.ReadUint8()
		if err != nil {
			return nil
		}
		switch nodeType {
		case 1:
			capabilities, ok := readLeafNodeCapabilities(r, nodes)
			if !ok {
				return nil
			}
			found = append(found, capabilities)
		case 2:
			// ParentNode: encryption_key, parent_hash, unmerged_leaves, all opaque<V>
			// as far as this walk is concerned.
			for range 3 {
				if _, err := r.ReadOpaque(); err != nil {
					return nil
				}
			}
		default:
			return nil
		}
	}
	return found
}

// leafCapabilitiesOfLeafNode reads blob as a bare LeafNode, which is what an Update proposal's
// body is, and returns its capabilities byte range.
func leafCapabilitiesOfLeafNode(blob []byte) ([]byte, bool) {
	r := syntax.NewReader(blob)
	capabilities, ok := readLeafNodeCapabilities(r, blob)
	if !ok || r.Done() != nil {
		return nil, false
	}
	return capabilities, true
}

// readLeafNodeCapabilities consumes one RFC 9420 section 7.2 LeafNode from r and returns the
// byte range its capabilities field occupies in raw, which must be the slice r was opened
// over. Only a BasicCredential is handled, which is every credential the vendored vectors
// carry and the only one this profile admits.
func readLeafNodeCapabilities(r *syntax.Reader, raw []byte) ([]byte, bool) {
	// encryption_key and signature_key
	for range 2 {
		if _, err := r.ReadOpaque(); err != nil {
			return nil, false
		}
	}
	credentialType, err := r.ReadUint16()
	if err != nil || credentialType != uint16(CredentialTypeBasic) {
		return nil, false
	}
	if _, err := r.ReadOpaque(); err != nil {
		return nil, false
	}
	start := r.Offset()
	// the five registry vectors, taken as opaque regions so this reader never depends on the
	// decoder it is here to check
	for range 5 {
		if _, err := r.ReadOpaque(); err != nil {
			return nil, false
		}
	}
	end := r.Offset()
	source, err := r.ReadUint8()
	if err != nil {
		return nil, false
	}
	switch source {
	case 1: // key_package: a Lifetime, which is two uint64
		for range 2 {
			if _, err := r.ReadUint64(); err != nil {
				return nil, false
			}
		}
	case 2: // update: nothing further
	case 3: // commit: parent_hash
		if _, err := r.ReadOpaque(); err != nil {
			return nil, false
		}
	default:
		return nil, false
	}
	// extensions<V> and the signature
	for range 2 {
		if _, err := r.ReadOpaque(); err != nil {
			return nil, false
		}
	}
	if start >= end || end > len(raw) {
		return nil, false
	}
	return raw[start:end], true
}

// upstreamRequiredCapabilitiesBodies is every required_capabilities extension body the mlswg
// group_info vectors carry, keyed by hex.
//
// This one goes through GroupContext and FindExtension, which have landed and have their own
// upstream goldens, rather than through a second hand written navigator. The four octets
// skipped are the MLSMessage version and wire_format that wrap a GroupInfo, and
// GroupContext.UnmarshalMLS consuming exactly its own fields is what lets the rest of the
// GroupInfo be ignored.
func upstreamRequiredCapabilitiesBodies(t *testing.T) map[string][]byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "vectors", "messages.json"))
	if err != nil {
		t.Fatalf("read messages.json: %v", err)
	}
	entries := []map[string]string{}
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("parse messages.json: %v", err)
	}
	found := map[string][]byte{}
	contexts := 0
	for _, entry := range entries {
		encoded, err := hex.DecodeString(entry["mls_group_info"])
		if err != nil || len(encoded) < 4 {
			continue
		}
		context := &GroupContext{}
		if err := context.UnmarshalMLS(syntax.NewReader(encoded[4:])); err != nil {
			continue
		}
		contexts++
		if data, ok := FindExtension(context.Extensions, ExtensionTypeRequiredCapabilities); ok {
			found[hex.EncodeToString(data)] = data
		}
	}
	if contexts == 0 {
		t.Fatal("no group context was decoded out of messages.json, so this scan read nothing")
	}
	if len(found) == 0 {
		t.Fatalf("%d upstream group contexts were decoded and none carried a required_capabilities extension, so this comparison is against an empty set",
			contexts)
	}
	t.Logf("%d upstream group contexts, %d distinct required_capabilities bodies", contexts, len(found))
	return found
}

// ---------------------------------------------------------------------------
// the goldens, checked against upstream and then against the encoder
// ---------------------------------------------------------------------------

// TestCapabilitiesHandDerivedGoldenMatchesTheUpstreamVectors checks the hand derivation
// against another implementation's bytes before anything is asserted against it. Both are
// statements of the section 7.2 encoding written without reference to this package -- one here
// from the RFC, one by the implementations that produced the mlswg vectors -- and agreeing is
// what makes either worth quoting.
func TestCapabilitiesHandDerivedGoldenMatchesTheUpstreamVectors(t *testing.T) {
	derived := handDerivedUpstreamCapabilitiesGolden()
	if len(derived) != 23 {
		t.Fatalf("the hand derivation is %d octets, the arithmetic in its comment says 23", len(derived))
	}
	upstream := upstreamLeafCapabilities(t)
	if _, held := upstream[hex.EncodeToString(derived)]; !held {
		t.Fatalf("the hand derived capabilities golden\n %x\nis not among the %d the vendored vectors carry:\n %v",
			derived, len(upstream), slices.Sorted(maps.Keys(upstream)))
	}
}

// TestCapabilitiesMarshalMatchesTheHandDerivedGoldens is the field order and prefix width pin.
// Two of the five vectors swapped, or a byte count written as an element count, changes every
// leaf node signature this implementation produces and verifies, and this is the cheapest
// place to see it.
func TestCapabilitiesMarshalMatchesTheHandDerivedGoldens(t *testing.T) {
	for name, testCase := range map[string]struct {
		value *Capabilities
		want  []byte
		size  int
	}{
		"upstream": {upstreamCapabilitiesGoldenValue(), handDerivedUpstreamCapabilitiesGolden(), 23},
		"profile":  {profileCapabilitiesGoldenValue(), handDerivedProfileCapabilitiesGolden(), 78},
	} {
		if len(testCase.want) != testCase.size {
			t.Fatalf("%s: the hand derivation is %d octets, the arithmetic in its comment says %d",
				name, len(testCase.want), testCase.size)
		}
		encoded, err := syntax.Marshal(testCase.value)
		if err != nil {
			t.Fatalf("%s: syntax.Marshal: %v", name, err)
		}
		if !bytes.Equal(encoded, testCase.want) {
			t.Errorf("%s: syntax.Marshal =\n %x\nwant\n %x", name, encoded, testCase.want)
		}
		decoded := &Capabilities{}
		if err := syntax.Unmarshal(testCase.want, decoded); err != nil {
			t.Fatalf("%s: syntax.Unmarshal: %v", name, err)
		}
		if !sameRegistryVectors(decoded, testCase.value) {
			t.Errorf("%s: the golden decoded to %s, want %s",
				name, describeRegistryVectors(decoded), describeRegistryVectors(testCase.value))
		}
	}
}

// TestCapabilitiesRoundTripsEveryUpstreamEncodingByteExact is the widest statement of the
// codec that costs nothing: every capabilities encoding another implementation wrote must
// decode here and re-encode to the same octets.
//
// It reaches what a golden cannot. The goldens are two structures; this is every one the
// vendored families contain, including a proposals vector naming a code point no registry
// entry of this package declares, which is the GREASE case a decoder that validated registry
// membership would refuse and nothing else here would notice.
func TestCapabilitiesRoundTripsEveryUpstreamEncodingByteExact(t *testing.T) {
	upstream := upstreamLeafCapabilities(t)
	if len(upstream) < 2 {
		t.Fatalf("the vendored vectors yielded %d distinct capabilities encodings; a single one cannot show that the field order is read the same way twice",
			len(upstream))
	}
	unregistered := 0
	declaredProposals := sortedValues(registryConstantsOfType(t, "ProposalType"))
	for _, name := range slices.Sorted(maps.Keys(upstream)) {
		encoded := upstream[name]
		decoded := &Capabilities{}
		if err := syntax.Unmarshal(encoded, decoded); err != nil {
			t.Errorf("%s: syntax.Unmarshal: %v", name, err)
			continue
		}
		reencoded, err := syntax.Marshal(decoded)
		if err != nil {
			t.Errorf("%s: syntax.Marshal: %v", name, err)
			continue
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Errorf("%s: re-encode =\n %x\nwant\n %x", name, reencoded, encoded)
		}
		for _, proposal := range decoded.Proposals {
			if !slices.Contains(declaredProposals, uint64(proposal)) {
				unregistered++
			}
		}
	}
	if unregistered == 0 {
		t.Error("no upstream capabilities carried a proposal type this package does not declare, so the GREASE case this sweep is worth most for was never reached")
	}
}

// TestRequiredCapabilitiesMarshalMatchesTheHandDerivedGoldens pins the section 11.1 field
// order, and the empty case against the mlswg group_info vectors.
func TestRequiredCapabilitiesMarshalMatchesTheHandDerivedGoldens(t *testing.T) {
	empty := handDerivedUpstreamRequiredCapabilitiesGolden()
	upstream := upstreamRequiredCapabilitiesBodies(t)
	if _, held := upstream[hex.EncodeToString(empty)]; !held {
		t.Fatalf("the hand derived empty required_capabilities golden %x is not among the %v the group_info vectors carry",
			empty, slices.Sorted(maps.Keys(upstream)))
	}
	for name, testCase := range map[string]struct {
		value *RequiredCapabilities
		want  []byte
		size  int
	}{
		"empty":   {&RequiredCapabilities{}, empty, 3},
		"profile": {profileRequiredCapabilitiesGoldenValue(), handDerivedProfileRequiredCapabilitiesGolden(), 9},
	} {
		if len(testCase.want) != testCase.size {
			t.Fatalf("%s: the hand derivation is %d octets, the arithmetic in its comment says %d",
				name, len(testCase.want), testCase.size)
		}
		encoded, err := syntax.Marshal(testCase.value)
		if err != nil {
			t.Fatalf("%s: syntax.Marshal: %v", name, err)
		}
		if !bytes.Equal(encoded, testCase.want) {
			t.Errorf("%s: syntax.Marshal =\n %x\nwant\n %x", name, encoded, testCase.want)
		}
		decoded := &RequiredCapabilities{}
		if err := syntax.Unmarshal(testCase.want, decoded); err != nil {
			t.Fatalf("%s: syntax.Unmarshal: %v", name, err)
		}
		if !sameRegistryVectors(decoded, testCase.value) {
			t.Errorf("%s: the golden decoded to %s, want %s",
				name, describeRegistryVectors(decoded), describeRegistryVectors(testCase.value))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(upstream)) {
		decoded := &RequiredCapabilities{}
		if err := syntax.Unmarshal(upstream[name], decoded); err != nil {
			t.Errorf("%s: syntax.Unmarshal an upstream body: %v", name, err)
			continue
		}
		reencoded, err := syntax.Marshal(decoded)
		if err != nil {
			t.Errorf("%s: syntax.Marshal: %v", name, err)
			continue
		}
		if !bytes.Equal(reencoded, upstream[name]) {
			t.Errorf("%s: re-encode = %x, want %x", name, reencoded, upstream[name])
		}
	}
}

// TestExtensionMarshalMatchesTheHandDerivedGoldens pins the section 6.3.1 entry framing and
// the extensions<V> vector's own prefix. The six octet entry is the one the mlswg group_info
// vectors carry, so the entry layout is held to another implementation, and the 68 octet one
// crosses the varint width boundary the published vectors do not reach.
func TestExtensionMarshalMatchesTheHandDerivedGoldens(t *testing.T) {
	for name, testCase := range map[string]struct {
		value *Extension
		want  []byte
		size  int
	}{
		"required capabilities": {
			&Extension{ExtensionType: ExtensionTypeRequiredCapabilities, ExtensionData: []byte{0x00, 0x00, 0x00}},
			handDerivedRequiredCapabilitiesExtensionGolden(), 6,
		},
		"long body": {
			&Extension{ExtensionType: ExtensionTypeUrmessageLeafKeys, ExtensionData: repeatByte(0x5a, 64)},
			handDerivedLongExtensionGolden(), 68,
		},
	} {
		if len(testCase.want) != testCase.size {
			t.Fatalf("%s: the hand derivation is %d octets, the arithmetic in its comment says %d",
				name, len(testCase.want), testCase.size)
		}
		encoded, err := syntax.Marshal(testCase.value)
		if err != nil {
			t.Fatalf("%s: syntax.Marshal: %v", name, err)
		}
		if !bytes.Equal(encoded, testCase.want) {
			t.Errorf("%s: syntax.Marshal =\n %x\nwant\n %x", name, encoded, testCase.want)
		}
	}

	// and the vector's own byte count, which is written by syntax.WriteVector rather than at
	// each of the five call sites that carry an extensions field
	w := syntax.NewWriter()
	if err := WriteExtensions(w, []Extension{
		{ExtensionType: ExtensionTypeRequiredCapabilities, ExtensionData: []byte{0x00, 0x00, 0x00}},
	}); err != nil {
		t.Fatalf("WriteExtensions: %v", err)
	}
	encoded, err := w.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if want := handDerivedExtensionsVectorGolden(); !bytes.Equal(encoded, want) {
		t.Fatalf("WriteExtensions = %x, want %x", encoded, want)
	}
	out, err := ReadExtensions(syntax.NewReader(encoded))
	if err != nil {
		t.Fatalf("ReadExtensions: %v", err)
	}
	if len(out) != 1 || out[0].ExtensionType != ExtensionTypeRequiredCapabilities ||
		!bytes.Equal(out[0].ExtensionData, []byte{0x00, 0x00, 0x00}) {
		t.Fatalf("ReadExtensions = %+v", out)
	}
}

// TestExtensionCarriesAnUnregisteredTypeUnchanged is the codec-decides-no-policy rule stated
// where it can fail: every code point outside the six this package declares must decode, be
// carried, and re-encode to the same octets.
//
// The class is derived as the complement of the declared one over a sample of the whole uint16
// space rather than as a couple of values somebody picked, because "unknown" is 65530 code
// points and a decoder that refused a RANGE of them -- say everything above 0xF003, which is
// the shape a private-use check takes -- passes a test naming two.
func TestExtensionCarriesAnUnregisteredTypeUnchanged(t *testing.T) {
	declared := sortedValues(registryConstantsOfType(t, "ExtensionType"))
	checked := 0
	for candidate := 0; candidate <= 0xffff; candidate += 7 {
		if slices.Contains(declared, uint64(candidate)) {
			continue
		}
		in := &Extension{ExtensionType: ExtensionType(candidate), ExtensionData: []byte{0xa5}}
		encoded, err := syntax.Marshal(in)
		if err != nil {
			t.Fatalf("%#04x: syntax.Marshal: %v", candidate, err)
		}
		out := &Extension{}
		if err := syntax.Unmarshal(encoded, out); err != nil {
			t.Fatalf("%#04x: syntax.Unmarshal: %v", candidate, err)
		}
		if out.ExtensionType != in.ExtensionType || !bytes.Equal(out.ExtensionData, in.ExtensionData) {
			t.Fatalf("%#04x: round trip = %+v, want %+v", candidate, out, in)
		}
		checked++
	}
	if checked < 9000 {
		t.Fatalf("only %d unregistered extension types were exercised, so the sweep read something other than the uint16 space", checked)
	}
}

// TestFindExtensionAnswersBothDirections states the lookup over the class it is asked about:
// for every extension type this package declares, a vector that holds it and a vector that
// does not.
//
// Both directions, and derived, because the two failures are symmetric and neither is visible
// from the other. A lookup that always reports found hands a caller an empty body for a
// required_capabilities that is not there; one that always reports absent makes every
// extension the group set unreachable. The bodies differ per entry so a lookup returning the
// wrong entry's body is a failure too.
func TestFindExtensionAnswersBothDirections(t *testing.T) {
	declared := registryConstantsOfType(t, "ExtensionType")
	types := []ExtensionType{}
	for _, value := range sortedValues(declared) {
		types = append(types, ExtensionType(value))
	}
	// a code point the package declares none of, so "absent" is also stated for a type the
	// vector could never hold
	types = append(types, ExtensionType(0xbeef))
	if len(types) < 3 {
		t.Fatalf("the derivation found %d extension types, so this sweep states almost nothing", len(types))
	}

	bodyFor := func(t ExtensionType) []byte { return []byte{byte(t >> 8), byte(t), 0x5a} }
	present := []Extension{}
	for _, extensionType := range types {
		present = append(present, Extension{ExtensionType: extensionType, ExtensionData: bodyFor(extensionType)})
	}
	for _, extensionType := range types {
		body, ok := FindExtension(present, extensionType)
		if !ok {
			t.Errorf("%#04x: FindExtension over a vector holding it reported absent", uint16(extensionType))
			continue
		}
		if !bytes.Equal(body, bodyFor(extensionType)) {
			t.Errorf("%#04x: FindExtension returned %x, want %x", uint16(extensionType), body, bodyFor(extensionType))
		}
		absent := slices.DeleteFunc(slices.Clone(present), func(e Extension) bool {
			return e.ExtensionType == extensionType
		})
		if body, ok := FindExtension(absent, extensionType); ok {
			t.Errorf("%#04x: FindExtension over a vector without it returned %x and reported found",
				uint16(extensionType), body)
		}
	}
	if _, ok := FindExtension(nil, ExtensionTypeRatchetTree); ok {
		t.Error("FindExtension reported found over a nil vector")
	}
	if _, ok := FindExtension([]Extension{}, ExtensionTypeRatchetTree); ok {
		t.Error("FindExtension reported found over an empty vector")
	}
	// present with an empty body is not absent, which is the whole reason the bool is
	// separate from the slice
	body, ok := FindExtension([]Extension{{ExtensionType: ExtensionTypeRatchetTree}}, ExtensionTypeRatchetTree)
	if !ok || len(body) != 0 {
		t.Errorf("an entry with an empty body reported (%x, %v), want (empty, true)", body, ok)
	}
}

// ---------------------------------------------------------------------------
// the refusal properties
// ---------------------------------------------------------------------------

// goldenExtensionEncodings, goldenCapabilitiesEncodings and goldenRequiredCapabilitiesEncodings
// are the valid encodings the refusal properties are stated over. Each set holds a hand
// derivation that another implementation also produced and one that reaches what the published
// vectors do not, so both the ordinary and the boundary shapes are swept.
func goldenExtensionEncodings() map[string][]byte {
	return map[string][]byte{
		"required capabilities entry": handDerivedRequiredCapabilitiesExtensionGolden(),
		"long body entry":             handDerivedLongExtensionGolden(),
	}
}

func goldenCapabilitiesEncodings() map[string][]byte {
	return map[string][]byte{
		"upstream": handDerivedUpstreamCapabilitiesGolden(),
		"profile":  handDerivedProfileCapabilitiesGolden(),
	}
}

func goldenRequiredCapabilitiesEncodings() map[string][]byte {
	return map[string][]byte{
		"empty":   handDerivedUpstreamRequiredCapabilitiesGolden(),
		"profile": handDerivedProfileRequiredCapabilitiesGolden(),
	}
}

// checkCodecRefusals states the three refusal properties every wire structure of this package
// owes, over one type and one set of valid encodings: a trailing octet is refused with
// syntax.ErrTrailingBytes, every proper prefix is refused rather than yielding a partly
// populated struct, and every single octet change is either refused or re-encodes to exactly
// the corrupted bytes.
//
// The third is the canonicality property and the one worth the most: accepted and silently
// changed is a second encoding of a structure whose first encoding somebody signed. Both of
// its outcomes are counted and both are required to occur across the set, because a decoder
// that refused everything satisfies it vacuously and so does a corpus that never reaches the
// accepting branch.
//
// Written once over the type parameter rather than three times, so the three structures cannot
// come to be held to three different versions of the same rule.
func checkCodecRefusals[T any, PT interface {
	*T
	syntax.Codec
}](t *testing.T, goldens map[string][]byte) {
	t.Helper()
	acceptedCorruptions, refusedCorruptions := 0, 0
	for _, name := range slices.Sorted(maps.Keys(goldens)) {
		full := goldens[name]
		if err := syntax.Unmarshal(full, PT(new(T))); err != nil {
			t.Fatalf("%s: the golden itself was refused (%v), so every property below proves nothing", name, err)
		}
		if err := syntax.Unmarshal(append(slices.Clone(full), 0x00), PT(new(T))); !errors.Is(err, syntax.ErrTrailingBytes) {
			t.Errorf("%s: a trailing octet gave err = %v, want ErrTrailingBytes", name, err)
		}
		for n := range len(full) {
			if err := syntax.Unmarshal(full[:n], PT(new(T))); err == nil {
				t.Errorf("%s: the %d octet prefix of %d was accepted, want an error", name, n, len(full))
			}
		}
		familyRefused := 0
		for position := range full {
			for delta := 1; delta < 256; delta++ {
				corrupted := slices.Clone(full)
				corrupted[position] = byte((int(full[position]) + delta) % 256)
				parsed := PT(new(T))
				if err := syntax.Unmarshal(corrupted, parsed); err != nil {
					refusedCorruptions++
					familyRefused++
					continue
				}
				reencoded, err := syntax.Marshal(parsed)
				if err != nil {
					t.Errorf("%s: an accepted corruption at %d failed to re-encode: %v", name, position, err)
					continue
				}
				if !bytes.Equal(reencoded, corrupted) {
					t.Fatalf("%s: the corruption at octet %d was accepted and re-encoded as\n %x\nrather than\n %x",
						name, position, reencoded, corrupted)
				}
				acceptedCorruptions++
			}
		}
		if familyRefused == 0 {
			t.Errorf("%s: no single octet change to it was refused, which cannot be true of a length prefixed encoding",
				name)
		}
	}
	if acceptedCorruptions == 0 {
		t.Error("every corruption was refused, so the canonicality half of this sweep never ran")
	}
	if refusedCorruptions == 0 {
		t.Error("no corruption was refused, so the decoder accepts every octet string this sweep produced")
	}
	t.Logf("%d corruptions accepted and re-encoded exactly, %d refused", acceptedCorruptions, refusedCorruptions)
}

func TestExtensionRefusesTrailingTruncatedAndNonCanonicalInput(t *testing.T) {
	checkCodecRefusals[Extension](t, goldenExtensionEncodings())
}

func TestCapabilitiesRefusesTrailingTruncatedAndNonCanonicalInput(t *testing.T) {
	checkCodecRefusals[Capabilities](t, goldenCapabilitiesEncodings())
}

func TestRequiredCapabilitiesRefusesTrailingTruncatedAndNonCanonicalInput(t *testing.T) {
	checkCodecRefusals[RequiredCapabilities](t, goldenRequiredCapabilitiesEncodings())
}

// ---------------------------------------------------------------------------
// the generated round trip corpus
// ---------------------------------------------------------------------------

// registryVectorShapes is the vector shapes one registry field is generated over, derived from
// the code points the package declares for that registry rather than from a list beside it: a
// constant added to a registry enters this corpus in the commit that declares it.
//
// The shapes are the ones the encoding branches on -- absent, empty, one element, every
// declared element plus the two boundary code points, and a body that crosses the octet width
// of the MLS varint at 63 and 64 octets.
func registryVectorShapes(t *testing.T, typeName string) [][]uint64 {
	t.Helper()
	declared := sortedValues(registryConstantsOfType(t, typeName))
	all := append(slices.Clone(declared), 0x0000, 0xffff)
	slices.Sort(all)
	all = slices.Compact(all)

	long := func(count int) []uint64 {
		out := make([]uint64, 0, count)
		for i := range count {
			out = append(out, uint64(0x0100+i))
		}
		return out
	}
	return [][]uint64{
		nil,
		{},
		{declared[0]},
		all,
		// 31 elements is 62 octets, the last body a one octet varint prefix expresses; 32 is
		// 64 and needs two. An encoder writing the prefix as a uint8 is correct for every
		// shape above and wrong for the one below it.
		long(31),
		long(32),
	}
}

// generatedRegistryStructs builds the round trip corpus for one structure whose every field is
// a slice of a registry type, by varying one field at a time over registryVectorShapes with
// the others held at a base, and then a full cross product over the first three shapes.
//
// One at a time plus a bounded cross product rather than the full one: six shapes over five
// fields is 7776 cases and every one of them costs a type check nothing, but the shapes that
// interact are the adjacent ones -- a length prefix read at the wrong width takes its extra
// octet from the field after it -- so the cross product is where the interaction is and the
// long bodies are where the width is.
func generatedRegistryStructs[T any](t *testing.T, typeNames []string) []*T {
	t.Helper()
	structType := reflect.TypeOf((*T)(nil)).Elem()
	if structType.NumField() != len(typeNames) {
		t.Fatalf("%s has %d fields and %d registry names were given, so this corpus varies fields that do not exist or misses ones that do",
			structType.Name(), structType.NumField(), len(typeNames))
	}
	shapes := make([][][]uint64, len(typeNames))
	for i, typeName := range typeNames {
		if got := structType.Field(i).Type.Elem().Name(); got != typeName {
			t.Fatalf("%s field %d is a slice of %s and the name given for it is %s",
				structType.Name(), i, got, typeName)
		}
		shapes[i] = registryVectorShapes(t, typeName)
	}

	build := func(pick []int) *T {
		value := new(T)
		element := reflect.ValueOf(value).Elem()
		for i := range pick {
			shape := shapes[i][pick[i]]
			if shape == nil {
				continue
			}
			field := element.Field(i)
			slice := reflect.MakeSlice(field.Type(), 0, len(shape))
			for _, code := range shape {
				item := reflect.New(field.Type().Elem()).Elem()
				item.SetUint(code)
				slice = reflect.Append(slice, item)
			}
			field.Set(slice)
		}
		return value
	}

	corpus := []*T{}
	base := make([]int, len(typeNames))
	for i := range typeNames {
		for shape := range shapes[i] {
			pick := slices.Clone(base)
			pick[i] = shape
			corpus = append(corpus, build(pick))
		}
	}
	// the bounded cross product: absent, empty and a one element vector in every field
	// combination, which is where a prefix read at the wrong width shows up as the field
	// after it taking the wrong bytes
	pick := make([]int, len(typeNames))
	var cross func(int)
	cross = func(depth int) {
		if depth == len(typeNames) {
			corpus = append(corpus, build(slices.Clone(pick)))
			return
		}
		for shape := 0; shape < 3; shape++ {
			pick[depth] = shape
			cross(depth + 1)
		}
	}
	cross(0)
	return corpus
}

// sameRegistryVectors reports whether two structures whose every field is a slice of a ~uint16
// registry carry the same code points in the same order.
//
// nil and empty count as equal, deliberately: the wire has one spelling for both, so a decoder
// that returns an empty slice where the caller supplied nil has not changed the value it
// describes. reflect.DeepEqual would report those as different and would make every corpus
// case holding a nil field a false failure.
func sameRegistryVectors(left any, right any) bool {
	l := reflect.ValueOf(left).Elem()
	r := reflect.ValueOf(right).Elem()
	if l.Type() != r.Type() {
		return false
	}
	for i := 0; i < l.NumField(); i++ {
		lf, rf := l.Field(i), r.Field(i)
		if lf.Len() != rf.Len() {
			return false
		}
		for j := 0; j < lf.Len(); j++ {
			if lf.Index(j).Uint() != rf.Index(j).Uint() {
				return false
			}
		}
	}
	return true
}

// describeRegistryVectors renders such a structure for a failure message.
func describeRegistryVectors(value any) string {
	element := reflect.ValueOf(value).Elem()
	parts := []string{}
	for i := 0; i < element.NumField(); i++ {
		codes := []string{}
		for j := 0; j < element.Field(i).Len(); j++ {
			codes = append(codes, fmt.Sprintf("%#04x", element.Field(i).Index(j).Uint()))
		}
		parts = append(parts, fmt.Sprintf("%s[%s]", element.Type().Field(i).Name, strings.Join(codes, " ")))
	}
	return strings.Join(parts, " ")
}

// checkRegistryStructRoundTrip states the byte exact round trip over a generated corpus: the
// encoding decodes to a value carrying the same code points, and re-encoding that value
// reproduces the octets exactly.
//
// Both halves, because either alone is satisfied by a defect the other catches. A byte exact
// re-encode alone is satisfied by a codec that dropped one field from both halves, since the
// octets it never wrote are the octets it never reads. A value comparison alone is satisfied by
// a codec whose length prefix is not minimal, since it decodes back to the same code points
// through bytes no peer would have written.
func checkRegistryStructRoundTrip[T any, PT interface {
	*T
	syntax.Codec
}](t *testing.T, corpus []*T) {
	t.Helper()
	if len(corpus) < 20 {
		t.Fatalf("the corpus holds %d cases, which is fewer than the generator's own axes produce, so it was built from a derivation that read nothing",
			len(corpus))
	}
	for _, value := range corpus {
		encoded, err := syntax.Marshal(PT(value))
		if err != nil {
			t.Fatalf("%s: syntax.Marshal: %v", describeRegistryVectors(value), err)
		}
		decoded := PT(new(T))
		if err := syntax.Unmarshal(encoded, decoded); err != nil {
			t.Fatalf("%s: syntax.Unmarshal: %v", describeRegistryVectors(value), err)
		}
		if !sameRegistryVectors(decoded, value) {
			t.Fatalf("round trip of %s gave %s", describeRegistryVectors(value), describeRegistryVectors(decoded))
		}
		reencoded, err := syntax.Marshal(decoded)
		if err != nil {
			t.Fatalf("%s: re-encode: %v", describeRegistryVectors(value), err)
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Fatalf("%s: re-encode =\n %x\nwant\n %x", describeRegistryVectors(value), reencoded, encoded)
		}
	}
	t.Logf("%d generated cases round tripped byte exact", len(corpus))
}

func TestCapabilitiesRoundTripsByteExactOverTheGeneratedCorpus(t *testing.T) {
	corpus := generatedRegistryStructs[Capabilities](t,
		[]string{"ProtocolVersion", "CipherSuite", "ExtensionType", "ProposalType", "CredentialType"})
	checkRegistryStructRoundTrip[Capabilities](t, corpus)
}

func TestRequiredCapabilitiesRoundTripsByteExactOverTheGeneratedCorpus(t *testing.T) {
	corpus := generatedRegistryStructs[RequiredCapabilities](t,
		[]string{"ExtensionType", "ProposalType", "CredentialType"})
	checkRegistryStructRoundTrip[RequiredCapabilities](t, corpus)
}

// checkEveryFieldChangesTheEncoding is the dropped field gate, stated over a class read off the
// struct type: for every field, two values differing only in that field must encode
// differently.
//
// A field dropped from BOTH codec halves is invisible to every round trip property in this
// file -- the octets never written are the octets never read, and the decode reproduces what
// the encode produced. What sees it is this: the field stops affecting the encoding at all.
//
// Derived over reflect rather than written out, because a field added to either structure
// enters the gate in the commit that declares it. That is rule 5 and it is not hypothetical
// here: Capabilities carries five vectors of the same shape, and a sixth would be exactly as
// easy to leave out of a hand written list as the fifth was.
func checkEveryFieldChangesTheEncoding[T any, PT interface {
	*T
	syntax.Codec
}](t *testing.T) {
	t.Helper()
	structType := reflect.TypeOf((*T)(nil)).Elem()
	if structType.NumField() == 0 {
		t.Fatalf("%s declares no field, so this gate judges nothing", structType.Name())
	}
	base := PT(new(T))
	baseValue := reflect.ValueOf(base).Elem()
	for i := 0; i < structType.NumField(); i++ {
		field := baseValue.Field(i)
		slice := reflect.MakeSlice(field.Type(), 1, 1)
		slice.Index(0).SetUint(0x0001)
		field.Set(slice)
	}
	baseEncoded, err := syntax.Marshal(base)
	if err != nil {
		t.Fatalf("%s: syntax.Marshal the base: %v", structType.Name(), err)
	}
	for i := 0; i < structType.NumField(); i++ {
		varied := PT(new(T))
		reflect.ValueOf(varied).Elem().Set(baseValue)
		field := reflect.ValueOf(varied).Elem().Field(i)
		slice := reflect.MakeSlice(field.Type(), 1, 1)
		slice.Index(0).SetUint(0x0002)
		field.Set(slice)

		encoded, err := syntax.Marshal(varied)
		if err != nil {
			t.Fatalf("%s.%s: syntax.Marshal: %v", structType.Name(), structType.Field(i).Name, err)
		}
		if bytes.Equal(encoded, baseEncoded) {
			t.Errorf("%s.%s: changing it left the encoding identical at %x, so nothing in the codec carries it",
				structType.Name(), structType.Field(i).Name, encoded)
			continue
		}
		decoded := PT(new(T))
		if err := syntax.Unmarshal(encoded, decoded); err != nil {
			t.Fatalf("%s.%s: syntax.Unmarshal: %v", structType.Name(), structType.Field(i).Name, err)
		}
		if !sameRegistryVectors(decoded, varied) {
			t.Errorf("%s.%s: it did not survive the round trip: %s came back as %s",
				structType.Name(), structType.Field(i).Name,
				describeRegistryVectors(varied), describeRegistryVectors(decoded))
		}
	}
}

func TestEveryCapabilitiesFieldChangesTheEncoding(t *testing.T) {
	checkEveryFieldChangesTheEncoding[Capabilities](t)
}

func TestEveryRequiredCapabilitiesFieldChangesTheEncoding(t *testing.T) {
	checkEveryFieldChangesTheEncoding[RequiredCapabilities](t)
}

// ---------------------------------------------------------------------------
// the registry code points
// ---------------------------------------------------------------------------

// registryCodePoints is what RFC 9420 section 17 assigns, transcribed from the RFC.
//
// The values and not merely the names, because two constants of one registry swapped compile,
// round trip, satisfy every predicate below and every symmetry property in this file, and are
// wrong in exactly the way that makes this implementation refuse a peer's Remove as an Update.
// Nothing else in this package would notice.
var registryCodePoints = map[string]map[string]uint64{
	"ProtocolVersion": {
		"ProtocolVersionMls10": 0x0001,
	},
	"CredentialType": {
		"CredentialTypeBasic": 0x0001,
	},
	"ProposalType": {
		"ProposalTypeReserved":               0x0000,
		"ProposalTypeAdd":                    0x0001,
		"ProposalTypeUpdate":                 0x0002,
		"ProposalTypeRemove":                 0x0003,
		"ProposalTypePreSharedKey":           0x0004,
		"ProposalTypeReInit":                 0x0005,
		"ProposalTypeExternalInit":           0x0006,
		"ProposalTypeGroupContextExtensions": 0x0007,
	},
	"ExtensionType": {
		"ExtensionTypeRatchetTree":             0x0002,
		"ExtensionTypeRequiredCapabilities":    0x0003,
		"ExtensionTypeExternalSenders":         0x0004,
		"ExtensionTypeUrmessageGroupPolicy":    0xF001,
		"ExtensionTypeUrmessageLeafKeys":       0xF002,
		"ExtensionTypeUrmessageOwnerSuccessor": 0xF003,
	},
}

// registryTypesDeclaredIn is every registry type extension.go declares, derived as every named
// type of that file whose underlying type is uint16.
//
// Derived and not listed, because the table above is a claim about a set and a claim about a
// set is worth what the set's derivation is worth. A fifth registry declared in this file with
// no entry in the table is then a failure naming it, rather than a registry whose code points
// nothing ever checked.
func registryTypesDeclaredIn(t *testing.T, file string) []string {
	t.Helper()
	declared := packageLevelDeclarations(t, ".")
	pkg := typeCheckedPackage(t)
	names := []string{}
	for name, declaredIn := range declared {
		if declaredIn != file {
			continue
		}
		typeName, isType := pkg.Scope().Lookup(name).(*types.TypeName)
		if !isType {
			continue
		}
		basic, isBasic := typeName.Type().Underlying().(*types.Basic)
		if !isBasic || basic.Kind() != types.Uint16 {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// TestEveryRegistryDeclaredHereHoldsTheCodePointsTheRfcAssigns is the enum value pin, stated in
// both directions over a derived class: extension.go's registry types are read off the type
// checker, the constants of each are read off it too, and the table above must hold exactly
// those names at exactly those values.
//
// Both directions matter and neither is redundant. A table richer than the source names a
// constant that no longer exists; a source richer than the table is a code point nothing
// checks, which is how a swapped pair survives. And a registry type with no table entry at all
// is the loud case, because that is the shape a new registry takes.
func TestEveryRegistryDeclaredHereHoldsTheCodePointsTheRfcAssigns(t *testing.T) {
	declared := registryTypesDeclaredIn(t, "extension.go")
	if len(declared) == 0 {
		t.Fatal("no registry type was derived from extension.go, which certainly declares several, so this gate read nothing")
	}
	if got, want := declared, slices.Sorted(maps.Keys(registryCodePoints)); !slices.Equal(got, want) {
		t.Fatalf("extension.go declares the registries %v and the table holds %v; a registry with no entry is one whose code points nothing checks",
			got, want)
	}
	for _, typeName := range declared {
		got := registryConstantsOfType(t, typeName)
		if want := registryCodePoints[typeName]; !maps.Equal(got, want) {
			t.Errorf("%s declares\n %v\nand RFC 9420 section 17 assigns\n %v", typeName, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// the validation surface
// ---------------------------------------------------------------------------

// requiredCapabilityFields pairs each RequiredCapabilities field with the Capabilities field
// that answers for it, matched by ELEMENT TYPE rather than by name.
//
// Matching by type is what makes this a derivation rather than a table: a fourth requirement
// added to RequiredCapabilities has to find a Capabilities field of its own element type or
// this fails, and a requirement silently answered by the wrong predicate is impossible because
// the two fields would have to carry the same registry.
//
// Every field of RequiredCapabilities must match exactly one field of Capabilities, and a
// field of either that does not is fatal rather than skipped, since a skipped requirement is
// exactly the hole this whole file exists to close.
func requiredCapabilityFields(t *testing.T) map[string]string {
	t.Helper()
	required := reflect.TypeOf(RequiredCapabilities{})
	capabilities := reflect.TypeOf(Capabilities{})
	pairs := map[string]string{}
	for i := 0; i < required.NumField(); i++ {
		field := required.Field(i)
		matches := []string{}
		for j := 0; j < capabilities.NumField(); j++ {
			if capabilities.Field(j).Type == field.Type {
				matches = append(matches, capabilities.Field(j).Name)
			}
		}
		if len(matches) != 1 {
			t.Fatalf("RequiredCapabilities.%s is a %s and Capabilities carries %d fields of that type (%v); the pairing has to be exactly one or a requirement is answered by the wrong predicate",
				field.Name, field.Type, len(matches), matches)
		}
		pairs[field.Name] = matches[0]
	}
	if len(pairs) != required.NumField() {
		t.Fatalf("%d of RequiredCapabilities' %d fields were paired", len(pairs), required.NumField())
	}
	return pairs
}

// mandatoryToImplement is every registry code point a member counts as supporting whether or
// not its own vector lists it, keyed by registry type and code point. RFC 9420 section 7.2
// makes the basic credential mandatory to implement, and it is the only such carve out in the
// specification.
//
// This is a written table and the sweeps below do NOT trust it: the same set is DERIVED by
// running each predicate against a member whose vectors are all empty, and the two must agree
// exactly. So a carve out that grows -- a predicate that started answering true for everything,
// which is precisely the permissive-in-the-wrong-direction defect this file is about -- fails
// by appearing in the derived set and not in this one, and a carve out that is removed fails
// the other way.
var mandatoryToImplement = map[string]bool{
	"CredentialType/0x0001": true,
}

// carveOutKey spells one entry of that table. Keyed by the registry TYPE rather than by a
// struct field name, because the two sweeps below reach the same code point from two different
// structs, and a key taken from either struct's field names would need a second name
// correspondence to be right.
func carveOutKey(registryName string, code uint64) string {
	return fmt.Sprintf("%s/%#04x", registryName, code)
}

// capabilityProbes is the code point set each requirement is exercised over: every constant the
// package declares for that registry, plus one the package declares for nothing.
//
// The GREASE probe is not decoration. The declared constants are small and dense, so a
// predicate comparing on a range rather than on equality -- everything below 0x0010 supported,
// say -- answers correctly for all of them.
func capabilityProbes(t *testing.T, typeName string) []uint64 {
	t.Helper()
	probes := sortedValues(registryConstantsOfType(t, typeName))
	const grease = 0xbeef
	if slices.Contains(probes, uint64(grease)) {
		t.Fatalf("%s declares %#04x, so it is not the unregistered probe this sweep needs", typeName, grease)
	}
	return append(probes, grease)
}

// buildCapabilities returns a Capabilities whose named field holds exactly the given code
// points and whose other fields are empty.
func buildCapabilities(fieldName string, codes []uint64) *Capabilities {
	value := &Capabilities{}
	field := reflect.ValueOf(value).Elem().FieldByName(fieldName)
	slice := reflect.MakeSlice(field.Type(), 0, len(codes))
	for _, code := range codes {
		item := reflect.New(field.Type().Elem()).Elem()
		item.SetUint(code)
		slice = reflect.Append(slice, item)
	}
	field.Set(slice)
	return value
}

// buildRequiredCapabilities returns a RequiredCapabilities whose named field requires exactly
// the given code point and which requires nothing else.
func buildRequiredCapabilities(fieldName string, code uint64) *RequiredCapabilities {
	value := &RequiredCapabilities{}
	field := reflect.ValueOf(value).Elem().FieldByName(fieldName)
	slice := reflect.MakeSlice(field.Type(), 1, 1)
	slice.Index(0).SetUint(code)
	field.Set(slice)
	return value
}

// TestSupportsAnswersBothDirectionsForEveryRequirementItCarries is the validation property, and
// it is stated in both directions because the two failures are symmetric, both silent, and
// neither visible to any codec property in this file.
//
// A check that accepts a member missing a required extension admits a member who cannot process
// the group's messages, and nothing reports an error until that member cannot decrypt. A check
// that rejects a member who has everything is a group nobody can join, and the failure names
// the member rather than the check. So for every requirement RequiredCapabilities carries and
// every code point the package declares for it, this asserts a member holding it is accepted
// and a member without it is refused.
//
// The class is derived twice over: the requirements from the struct type, the code points from
// the type checker. A list of either would be the hand written class rule 5 objects to, and
// Capabilities is five vectors of one shape, which is the easiest possible thing to write four
// of.
func TestSupportsAnswersBothDirectionsForEveryRequirementItCarries(t *testing.T) {
	pairs := requiredCapabilityFields(t)
	requiredType := reflect.TypeOf(RequiredCapabilities{})
	derivedCarveOuts := map[string]bool{}
	registriesSwept := map[string]bool{}
	accepted, refused := 0, 0
	for _, requirement := range slices.Sorted(maps.Keys(pairs)) {
		capabilityField := pairs[requirement]
		field, found := requiredType.FieldByName(requirement)
		if !found {
			t.Fatalf("RequiredCapabilities declares no field %s", requirement)
		}
		registry := field.Type.Elem().Name()
		registriesSwept[registry] = true
		for _, code := range capabilityProbes(t, registry) {
			rc := buildRequiredCapabilities(requirement, code)

			// the member who has it
			holder := buildCapabilities(capabilityField, []uint64{code})
			if err := holder.Supports(rc); err != nil {
				t.Errorf("%s %#04x: a member listing it was refused with %v; a requirement nobody can satisfy is a group nobody can join",
					requirement, code, err)
			} else {
				accepted++
			}

			// the member who does not
			without := buildCapabilities(capabilityField, nil)
			err := without.Supports(rc)
			if err == nil {
				derivedCarveOuts[carveOutKey(registry, code)] = true
				continue
			}
			refused++
			if !errors.Is(err, errMissingRequiredCapability) {
				t.Errorf("%s %#04x: a member without it was refused with %v, want errMissingRequiredCapability",
					requirement, code, err)
			}
		}
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("%d requirements were accepted and %d refused; a sweep that never reached one of the two directions states only the other",
			accepted, refused)
	}
	// restricted to the registries this sweep reaches: versions and ciphersuites are not
	// required of a member through RequiredCapabilities at all, so a carve out in one of
	// those is the predicate sweep's to judge and would be a false failure here.
	expected := map[string]bool{}
	for key := range mandatoryToImplement {
		if registriesSwept[strings.SplitN(key, "/", 2)[0]] {
			expected[key] = true
		}
	}
	if !maps.Equal(derivedCarveOuts, expected) {
		t.Errorf("a member with empty capabilities is accepted for %v and the mandatory to implement set reachable from a requirement is %v; a carve out that grew is a predicate answering true for something the member never claimed",
			slices.Sorted(maps.Keys(derivedCarveOuts)), slices.Sorted(maps.Keys(expected)))
	}
	t.Logf("%d (requirement, code point) pairs accepted with it, %d refused without it, %d carve outs",
		accepted, refused, len(derivedCarveOuts))
}

// TestSupportsAcceptsAMemberThatHasEverythingAndRefusesOneShortOfAnything states the whole
// check rather than one requirement at a time.
//
// The one-at-a-time sweep above cannot see a Supports that stops at its first satisfied loop:
// each of its RequiredCapabilities names exactly one requirement, so a body that returned nil
// after the extensions loop passes every case it produces. This requires all three at once,
// then drops one requirement at a time from the member and requires a refusal each time.
func TestSupportsAcceptsAMemberThatHasEverythingAndRefusesOneShortOfAnything(t *testing.T) {
	pairs := requiredCapabilityFields(t)
	full := &Capabilities{}
	rc := &RequiredCapabilities{}
	// a probe per requirement, none of them a carve out, so dropping any one has to be
	// visible
	probes := map[string]uint64{}
	for _, requirement := range slices.Sorted(maps.Keys(pairs)) {
		probes[requirement] = 0xbeef
		fullField := reflect.ValueOf(full).Elem().FieldByName(pairs[requirement])
		slice := reflect.MakeSlice(fullField.Type(), 1, 1)
		slice.Index(0).SetUint(probes[requirement])
		fullField.Set(slice)

		rcField := reflect.ValueOf(rc).Elem().FieldByName(requirement)
		rcSlice := reflect.MakeSlice(rcField.Type(), 1, 1)
		rcSlice.Index(0).SetUint(probes[requirement])
		rcField.Set(rcSlice)
	}
	if len(probes) == 0 {
		t.Fatal("RequiredCapabilities carries no requirement, so this states nothing")
	}
	if err := full.Supports(rc); err != nil {
		t.Fatalf("a member listing every requirement was refused with %v", err)
	}
	if err := full.Supports(nil); err != nil {
		t.Errorf("a nil requirement was refused with %v; a group carrying no required_capabilities requires nothing", err)
	}
	if err := (&Capabilities{}).Supports(&RequiredCapabilities{}); err != nil {
		t.Errorf("an empty requirement was refused with %v", err)
	}
	for _, requirement := range slices.Sorted(maps.Keys(pairs)) {
		short := &Capabilities{}
		reflect.ValueOf(short).Elem().Set(reflect.ValueOf(full).Elem())
		reflect.ValueOf(short).Elem().FieldByName(pairs[requirement]).Set(
			reflect.MakeSlice(reflect.ValueOf(short).Elem().FieldByName(pairs[requirement]).Type(), 0, 0))
		err := short.Supports(rc)
		if !errors.Is(err, errMissingRequiredCapability) {
			t.Errorf("a member short of %s alone gave err = %v, want errMissingRequiredCapability; a loop that is never reached is a requirement that is never checked",
				requirement, err)
		}
	}
}

// TestEverySupportsPredicateAnswersBothDirections states the five leaf predicates the way the
// whole check is stated, because two of them -- versions and ciphersuites -- are not reachable
// through RequiredCapabilities at all and would otherwise be judged by nothing.
//
// The predicates are derived from Capabilities' own fields: each field is a slice of one
// registry, and the predicate for it is the method taking that registry's type. A sixth field
// added to Capabilities without a predicate fails here rather than being quietly unjudged.
func TestEverySupportsPredicateAnswersBothDirections(t *testing.T) {
	capabilitiesType := reflect.TypeOf(Capabilities{})
	pointerType := reflect.TypeOf(&Capabilities{})
	derivedCarveOuts := map[string]bool{}
	judged := 0
	for i := 0; i < capabilitiesType.NumField(); i++ {
		field := capabilitiesType.Field(i)
		registry := field.Type.Elem()
		predicates := []reflect.Method{}
		for m := 0; m < pointerType.NumMethod(); m++ {
			method := pointerType.Method(m)
			if !strings.HasPrefix(method.Name, "Supports") || method.Type.NumIn() != 2 {
				continue
			}
			if method.Type.In(1) == registry && method.Type.NumOut() == 1 && method.Type.Out(0).Kind() == reflect.Bool {
				predicates = append(predicates, method)
			}
		}
		if len(predicates) != 1 {
			t.Fatalf("Capabilities.%s is a slice of %s and %d Supports predicates take that type (%v); one field, one predicate",
				field.Name, registry.Name(), len(predicates), predicates)
		}
		predicate := predicates[0]
		for _, code := range capabilityProbes(t, registry.Name()) {
			probe := reflect.New(registry).Elem()
			probe.SetUint(code)
			holder := buildCapabilities(field.Name, []uint64{code})
			if !predicate.Func.Call([]reflect.Value{reflect.ValueOf(holder), probe})[0].Bool() {
				t.Errorf("%s(%#04x) over a member listing it = false", predicate.Name, code)
			}
			without := buildCapabilities(field.Name, nil)
			if predicate.Func.Call([]reflect.Value{reflect.ValueOf(without), probe})[0].Bool() {
				derivedCarveOuts[carveOutKey(registry.Name(), code)] = true
			}
			judged++
		}
	}
	if judged == 0 {
		t.Fatal("no predicate was judged, so this gate read nothing off the type")
	}
	// this sweep reaches all five registries, so it owns the exact comparison: every carve out
	// the code makes has to be one the table argues for, and every one the table argues for has
	// to still be made.
	if !maps.Equal(derivedCarveOuts, mandatoryToImplement) {
		t.Errorf("the predicates answer true for %v over a member listing nothing, and the mandatory to implement set is %v",
			slices.Sorted(maps.Keys(derivedCarveOuts)), slices.Sorted(maps.Keys(mandatoryToImplement)))
	}
	t.Logf("%d (predicate, code point) pairs judged in both directions, %d carve outs",
		judged, len(derivedCarveOuts))
}

// ---------------------------------------------------------------------------
// the name owed to the validation plan
// ---------------------------------------------------------------------------

// TestNoValidationOwnedNameHasLandedBesideItsStandIn fails on the commit that lands the real
// ErrMissingRequiredCapability, which is what stops the unexported stand in outliving it.
//
// Package mls is one package, so two exported declarations of one name would be a compile
// error -- the loud half. The quiet half is the one this closes: the stand in stays, the
// validation plan's sentinel lands beside it, this file's refusals keep answering to a value
// no caller outside the package can match, and errors.Is in the commit path reports false with
// nothing to say about it.
//
// The owed pair is derived from extension.go rather than listed. Every unexported err-prefixed
// declaration of that file is a stand in for the exported name of the same spelling, so a
// second one added by a later task is watched without anybody editing this.
func TestNoValidationOwnedNameHasLandedBesideItsStandIn(t *testing.T) {
	declared := packageLevelDeclarations(t, ".")
	standIns := []string{}
	for name, file := range declared {
		if file != "extension.go" || !strings.HasPrefix(name, "err") {
			continue
		}
		standIns = append(standIns, name)
	}
	slices.Sort(standIns)
	if len(standIns) == 0 {
		t.Fatal("extension.go declares no unexported error stand in, and it certainly declares errMissingRequiredCapability, so this scan read something other than that file")
	}
	for _, name := range standIns {
		owed := "Err" + strings.TrimPrefix(name, "err")
		if file, landed := declared[owed]; landed {
			t.Errorf("%s has landed in %s and extension.go still carries the stand in %s; replace every use with the validation plan's sentinel and delete the stand in in the same commit",
				owed, file, name)
		}
	}
	t.Logf("%d stand in(s) still owed to the validation plan: %v", len(standIns), standIns)
}

// TestSupportsRefusalAnswersOnlyItsOwnSentinel keeps the stand in from being read as something
// else. It is wrapped with a detail naming the code point, so errors.Is has to hold through the
// wrap, and it must not answer to any sentinel of the plans that already have error files.
func TestSupportsRefusalAnswersOnlyItsOwnSentinel(t *testing.T) {
	caps := &Capabilities{}
	err := caps.Supports(&RequiredCapabilities{ExtensionTypes: []ExtensionType{ExtensionTypeUrmessageLeafKeys}})
	if !errors.Is(err, errMissingRequiredCapability) {
		t.Fatalf("err = %v, want errMissingRequiredCapability", err)
	}
	if !strings.Contains(err.Error(), "0xf002") {
		t.Errorf("err = %q and does not name the code point that failed; a caller told only that something is missing has to diff two vectors to find out what",
			err)
	}
	for _, class := range []map[string]error{treeOwnedErrors, treeMathOwnedErrors, keyScheduleOwnedErrors, cryptoOwnedErrors} {
		for _, name := range slices.Sorted(maps.Keys(class)) {
			if errors.Is(err, class[name]) {
				t.Errorf("the missing capability refusal answers to %s, and no plan argues for a wrap between a membership rule and that layer",
					name)
			}
		}
	}
}
