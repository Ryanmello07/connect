package mls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// ---------------------------------------------------------------------------
// the value every golden and every sweep below is built from
// ---------------------------------------------------------------------------

// testLeafNodeTemplate is one leaf with every field populated and every field DIFFERENT from
// every other field of its own width.
//
// Both halves of that matter. A leaf whose encryption key and signature key held the same
// octets would be encoded identically by a codec that wrote one of them twice, and by one that
// swapped them, so the goldens below would pin nothing. And a leaf missing a field cannot show
// that the field is written at all.
//
// The two variant fields are populated whatever the source is, which is the shape the
// "encoded under the wrong source" mutation needs: under update this leaf carries a lifetime
// and a parent hash that must NOT appear in its encoding, and a codec that wrote either one
// produces bytes the update golden does not hold.
func testLeafNodeTemplate() *LeafNode {
	return &LeafNode{
		EncryptionKey: HpkePublicKey(repeatByte(0x11, 32)),
		SignatureKey:  SignaturePublicKey(repeatByte(0x22, 32)),
		Credential:    Credential{CredentialType: CredentialTypeBasic, Identity: []byte("alice")},
		Capabilities: Capabilities{
			Versions:     []ProtocolVersion{ProtocolVersionMls10},
			CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20Sha256Ed25519},
			Extensions:   []ExtensionType{ExtensionTypeUrmessageLeafKeys},
			// empty and NOT nil, and in the middle of the five on purpose. Empty is what
			// separates the five capability vectors' order -- an encoder that wrote them in
			// any other order still writes five prefixes, and only a case where they differ
			// can tell the orders apart -- and non nil is what lets the decoded value be
			// compared whole, since ReadVector never answers nil.
			Proposals:   []ProposalType{},
			Credentials: []CredentialType{CredentialTypeBasic},
		},
		Lifetime:   Lifetime{NotBefore: 1000, NotAfter: 2000},
		ParentHash: repeatByte(0x44, 32),
		Extensions: []Extension{{ExtensionType: ExtensionTypeUrmessageLeafKeys, ExtensionData: []byte("k")}},
		Signature:  repeatByte(0x33, 64),
	}
}

// testLeafNodeOfSource is that template under one source. Every call answers fresh storage, so
// a sweep that mutates what it was handed cannot reach the next case through a shared array.
func testLeafNodeOfSource(source LeafNodeSource) *LeafNode {
	leaf := testLeafNodeTemplate()
	leaf.LeafNodeSource = source
	return leaf
}

// ---------------------------------------------------------------------------
// the hand derived goldens
// ---------------------------------------------------------------------------

// handDerivedLeafNodeCommon is the RFC 9420 section 7.2 prefix every source carries, written
// out from the RFC rather than read back through the encoder:
//
//	encryption_key<V>   32 octets    -> 20 11*32                        33
//	signature_key<V>    32 octets    -> 20 22*32                        33
//	credential:
//	  credential_type   uint16       -> 0001                             2
//	  identity<V>       5 octets     -> 05 "alice"                       6
//	capabilities:
//	  versions<V>       1 x uint16   -> 02 0001                          3
//	  ciphersuites<V>   1 x uint16   -> 02 0003                          3
//	  extensions<V>     1 x uint16   -> 02 f002                          3
//	  proposals<V>      empty        -> 00                               1
//	  credentials<V>    1 x uint16   -> 02 0001                          3
//	leaf_node_source    uint8        -> 01 | 02 | 03                     1
//
// 33 + 33 + 8 + 13 + 1 = 88 octets.
//
// The capabilities vector prefixes count BYTES and not code points, which is the single
// easiest thing in this encoding to get wrong and the one a round trip cannot see: an encoder
// writing 01 for one code point and a decoder reading one code point per unit agree with each
// other and with nothing else.
func handDerivedLeafNodeCommon(source LeafNodeSource) []byte {
	return joinBytes(
		[]byte{0x20}, repeatByte(0x11, 32),
		[]byte{0x20}, repeatByte(0x22, 32),
		[]byte{0x00, 0x01}, []byte{0x05}, []byte("alice"),
		[]byte{0x02}, []byte{0x00, 0x01},
		[]byte{0x02}, []byte{0x00, 0x03},
		[]byte{0x02}, []byte{0xf0, 0x02},
		[]byte{0x00},
		[]byte{0x02}, []byte{0x00, 0x01},
		[]byte{uint8(source)},
	)
}

// handDerivedLeafNodeTail is what follows the variant, for every source:
//
//	extensions<V>  one entry: f002 + 01 "k" = 4 octets -> 04 f002 016b   5
//	signature<V>   64 octets                           -> 4040 33*64    66
//
// 5 + 66 = 71 octets.
//
// The signature is 64 octets on purpose. That is the first length whose varint prefix is two
// octets rather than one, so a WriteOpaqueLP in place of WriteOpaque -- which would write
// 00000040 -- moves the total by two, and a fixed one octet prefix moves it by one. Neither is
// visible to a round trip, because this implementation would read back whatever it wrote.
func handDerivedLeafNodeTail() []byte {
	return joinBytes(
		[]byte{0x04}, []byte{0xf0, 0x02}, []byte{0x01}, []byte("k"),
		[]byte{0x40, 0x40}, repeatByte(0x33, 64),
	)
}

// handDerivedLeafNodeGolden is the whole leaf under one source: the common prefix, the variant
// the source selects, and the tail.
//
//	key_package  88 + Lifetime  16 + 71 = 175
//	update       88 + nothing    0 + 71 = 159
//	commit       88 + parent_hash 33 + 71 = 192
//
// The Lifetime is two uint64 written big endian and NOT length prefixed, since the structure
// fixes their width: not_before 1000 -> 00000000000003e8, not_after 2000 -> 00000000000007d0.
// The parent hash IS length prefixed, at 32 octets -> 20 44*32.
func handDerivedLeafNodeGolden(source LeafNodeSource) []byte {
	variant := []byte{}
	switch source {
	case LeafNodeSourceKeyPackage:
		variant = joinBytes(
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8},
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd0},
		)
	case LeafNodeSourceUpdate:
	case LeafNodeSourceCommit:
		variant = joinBytes([]byte{0x20}, repeatByte(0x44, 32))
	}
	return joinBytes(handDerivedLeafNodeCommon(source), variant, handDerivedLeafNodeTail())
}

// handDerivedLeafNodeSizes is the arithmetic in the comment above, stated separately so that a
// derivation edited without its comment fails rather than redefining what it is compared to.
var handDerivedLeafNodeSizes = map[LeafNodeSource]int{
	LeafNodeSourceKeyPackage: 175,
	LeafNodeSourceUpdate:     159,
	LeafNodeSourceCommit:     192,
}

// TestLeafNodeMarshalMatchesTheHandDerivedGoldens is the field order and prefix width pin, and
// the one test in this file a symmetric edit cannot survive.
//
// Two fields swapped in BOTH halves of the codec round trips perfectly, re-encodes byte exact
// against every published vector, and is invisible to every property in this file except this
// one: what separates the two orders is a statement of the encoding written without reference
// to the code, which is what this is.
func TestLeafNodeMarshalMatchesTheHandDerivedGoldens(t *testing.T) {
	for _, source := range leafNodeSources(t) {
		want := handDerivedLeafNodeGolden(source)
		size, stated := handDerivedLeafNodeSizes[source]
		if !stated {
			t.Fatalf("source %d has no hand derived size, so the derivation for it is compared only against itself", source)
		}
		if len(want) != size {
			t.Fatalf("source %d: the hand derivation is %d octets, the arithmetic in its comment says %d",
				source, len(want), size)
		}
		encoded, err := syntax.Marshal(testLeafNodeOfSource(source))
		if err != nil {
			t.Fatalf("source %d: Marshal: %v", source, err)
		}
		if !bytes.Equal(encoded, want) {
			t.Errorf("source %d: Marshal =\n %x\nwant\n %x", source, encoded, want)
		}
		decoded := &LeafNode{}
		if err := syntax.Unmarshal(want, decoded); err != nil {
			t.Fatalf("source %d: Unmarshal the golden: %v", source, err)
		}
		if !sameLeafNode(decoded, decodedFormOf(t, testLeafNodeOfSource(source))) {
			t.Errorf("source %d: the golden decoded to\n %s\nwant\n %s",
				source, describeLeafNode(decoded), describeLeafNode(decodedFormOf(t, testLeafNodeOfSource(source))))
		}
	}
}

// ---------------------------------------------------------------------------
// the variant table, and the field class derived off the type
// ---------------------------------------------------------------------------

// leafNodeVariantPaths is the RFC 9420 section 7.2 select, written as the field paths each
// source carries.
//
// It is a statement about the protocol and cannot be derived from the Go type, which is why it
// is written down -- but it is not trusted to be complete. leafNodeCodecFieldPaths derives the
// field class off the struct and leafNodeSources derives the source class off the package's own
// constants, and TestEveryLeafNodeFieldChangesTheEncodingOfTheSourceThatCarriesIt requires this
// table to cover both exactly. A field or a source added later fails there rather than being
// passed over.
var leafNodeVariantPaths = map[LeafNodeSource][]string{
	LeafNodeSourceKeyPackage: {"Lifetime.NotBefore", "Lifetime.NotAfter"},
	LeafNodeSourceUpdate:     {},
	LeafNodeSourceCommit:     {"ParentHash"},
}

// leafNodeSources is every LeafNodeSource constant this package declares, read off the
// declarations rather than typed out, so a fourth source is swept by everything below on the
// commit that declares it.
func leafNodeSources(t *testing.T) []LeafNodeSource {
	t.Helper()
	sources := []LeafNodeSource{}
	for _, value := range sortedValues(registryConstantsOfType(t, "LeafNodeSource")) {
		sources = append(sources, LeafNodeSource(value))
	}
	if len(sources) == 0 {
		t.Fatal("no LeafNodeSource constant was derived, so every sweep below runs over nothing")
	}
	return sources
}

// leafNodeDelegatedFieldTypes answers whether a field's type carries a codec of its own.
//
// The distinction decides how deep the field walk goes, and it is a property of the type rather
// than a list: Credential and Capabilities implement syntax.Marshaler, so LeafNode delegates
// their bytes to them and their internal field order is their own file's problem. Lifetime does
// not, so LeafNode's codec writes its two fields itself and they are LeafNode's to get wrong.
func leafNodeFieldIsDelegated(fieldType reflect.Type) bool {
	marshaler := reflect.TypeOf((*syntax.Marshaler)(nil)).Elem()
	return reflect.PointerTo(fieldType).Implements(marshaler)
}

// leafNodeCodecFieldPaths is every field path LeafNode's own codec is responsible for writing,
// derived by walking the struct definition.
//
// Derived and not enumerated, for the reason rule 5 names: a hand written field list understates
// the class the moment a field is added, and a "every field is covered" gate reading a stale
// list reports exactly what a complete one reports. The walk descends into a struct field only
// when that field has no codec of its own, so Lifetime contributes two paths and Credential
// contributes one.
func leafNodeCodecFieldPaths(t *testing.T) []string {
	t.Helper()
	paths := leafNodeFieldPathsOf(reflect.TypeOf(LeafNode{}), "")
	if len(paths) == 0 {
		t.Fatal("the field walk found no path on LeafNode, so every sweep reading it demands nothing")
	}
	return paths
}

func leafNodeFieldPathsOf(structType reflect.Type, prefix string) []string {
	paths := []string{}
	for i := 0; i < structType.NumField(); i += 1 {
		field := structType.Field(i)
		name := prefix + field.Name
		if field.Type.Kind() == reflect.Struct && !leafNodeFieldIsDelegated(field.Type) {
			paths = append(paths, leafNodeFieldPathsOf(field.Type, name+".")...)
			continue
		}
		paths = append(paths, name)
	}
	return paths
}

// leafNodeFieldAt navigates a dotted path to an addressable value inside one leaf.
func leafNodeFieldAt(leaf *LeafNode, path string) reflect.Value {
	value := reflect.ValueOf(leaf).Elem()
	for _, name := range strings.Split(path, ".") {
		value = value.FieldByName(name)
	}
	return value
}

// ---------------------------------------------------------------------------
// the edits the field sweep is built out of
// ---------------------------------------------------------------------------

// leafNodeEdit is one way of making a field different, named for the failure message.
type leafNodeEdit struct {
	name  string
	apply func(v reflect.Value)
}

// leafNodeEditsOf answers every edit that makes one value different from what it was, derived
// off its kind rather than written per field.
//
// More than one edit per value on purpose. A slice can be made different by changing an element
// OR by changing its length, and those are caught by different defects: an encoder that wrote a
// fixed number of octets misses the second, and one that wrote the length and not the content
// misses the first.
func leafNodeEditsOf(prefix string, v reflect.Value, sources []LeafNodeSource) []leafNodeEdit {
	if v.Type() == reflect.TypeOf(LeafNodeSource(0)) {
		edits := []leafNodeEdit{}
		for _, source := range sources {
			if LeafNodeSource(v.Uint()) == source {
				continue
			}
			edits = append(edits, leafNodeEdit{
				name:  fmt.Sprintf("%s = %d", prefix, source),
				apply: func(field reflect.Value) { field.SetUint(uint64(source)) },
			})
		}
		return edits
	}
	switch v.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return []leafNodeEdit{{
			name:  prefix + " + 1",
			apply: func(field reflect.Value) { field.SetUint(field.Uint() + 1) },
		}}
	case reflect.Slice:
		edits := []leafNodeEdit{{
			name: prefix + " grown by one element",
			apply: func(field reflect.Value) {
				field.Set(reflect.Append(field, reflect.Zero(field.Type().Elem())))
			},
		}}
		if v.Len() == 0 {
			return edits
		}
		edits = append(edits, leafNodeEdit{
			name:  prefix + " shortened by one element",
			apply: func(field reflect.Value) { field.Set(field.Slice(0, field.Len()-1)) },
		})
		for _, inner := range leafNodeEditsOf(prefix+"[0]", v.Index(0), sources) {
			edits = append(edits, leafNodeEdit{
				name:  inner.name,
				apply: func(field reflect.Value) { inner.apply(field.Index(0)) },
			})
		}
		return edits
	case reflect.Struct:
		edits := []leafNodeEdit{}
		for i := 0; i < v.NumField(); i += 1 {
			index := i
			for _, inner := range leafNodeEditsOf(prefix+"."+v.Type().Field(i).Name, v.Field(i), sources) {
				edits = append(edits, leafNodeEdit{
					name:  inner.name,
					apply: func(field reflect.Value) { inner.apply(field.Field(index)) },
				})
			}
		}
		return edits
	default:
		return nil
	}
}

// ---------------------------------------------------------------------------
// every field changes the encoding of the source that carries it, and no other
// ---------------------------------------------------------------------------

// TestEveryLeafNodeFieldChangesTheEncodingOfTheSourceThatCarriesIt is the property a byte exact
// round trip is incapable of stating.
//
// A field dropped from BOTH halves of the codec round trips byte exact while being lost, and a
// variant field written under the wrong source round trips just as cleanly. What separates them
// is whether the encoding DEPENDS on the field: two leaves differing only in field i must encode
// differently when the source carries that field, and identically when it does not.
//
// Both directions are asserted, and the second is the one that catches a variant encoded under
// the wrong source: a parent hash written under update makes an update leaf's encoding depend on
// a field update does not carry, and this fails naming it.
//
// The field class is derived off the struct definition and the source class off the package's
// constants, so the table this compares against has to cover both exactly or this fails first.
func TestEveryLeafNodeFieldChangesTheEncodingOfTheSourceThatCarriesIt(t *testing.T) {
	sources := leafNodeSources(t)
	paths := leafNodeCodecFieldPaths(t)

	// the table covers the derived source class exactly
	if got, want := slices.Sorted(maps.Keys(leafNodeVariantPaths)), sources; !slices.Equal(got, want) {
		t.Fatalf("leafNodeVariantPaths names sources %v and this package declares %v; a source with no row is one no branch below judges",
			got, want)
	}
	// and every path is either common to all sources or named as some source's variant
	variant := map[string]LeafNodeSource{}
	for _, source := range sources {
		for _, path := range leafNodeVariantPaths[source] {
			if !slices.Contains(paths, path) {
				t.Fatalf("leafNodeVariantPaths names %s under source %d and LeafNode has no such field", path, source)
			}
			if already, seen := variant[path]; seen {
				t.Fatalf("%s is named as a variant field of source %d and of source %d", path, already, source)
			}
			variant[path] = source
		}
	}

	covered := map[string]bool{}
	for _, source := range sources {
		base := testLeafNodeOfSource(source)
		encoded, err := syntax.Marshal(base)
		if err != nil {
			t.Fatalf("source %d: Marshal: %v", source, err)
		}
		for _, path := range paths {
			carried := true
			if owner, isVariant := variant[path]; isVariant {
				carried = owner == source
			}
			edits := leafNodeEditsOf(path, leafNodeFieldAt(base, path), sources)
			if len(edits) == 0 {
				t.Errorf("no edit was derived for %s, so nothing below observed it", path)
				continue
			}
			observed := false
			encodable := 0
			for _, edit := range edits {
				mutated := testLeafNodeOfSource(source)
				edit.apply(leafNodeFieldAt(mutated, path))
				changed, err := syntax.Marshal(mutated)
				if err != nil {
					// a semantic refusal rather than a different encoding: the credential
					// type outside the profile is the one edit here that produces one, and
					// an encoder that refuses is not an encoder that ignored the field
					continue
				}
				encodable += 1
				if !bytes.Equal(changed, encoded) {
					observed = true
					covered[path] = true
					continue
				}
				if carried {
					continue
				}
				// the field is not part of this source's encoding and the edit confirmed it
			}
			if encodable == 0 {
				t.Errorf("source %d: every edit to %s was refused by the encoder, so this field was never observed", source, path)
				continue
			}
			if carried && !observed {
				t.Errorf("source %d: %d edits to %s all left the encoding identical, so a leaf carrying that field is encoded without it",
					source, encodable, path)
			}
			if !carried && observed {
				t.Errorf("source %d: an edit to %s changed the encoding, and source %d does not carry that field",
					source, path, source)
			}
		}
	}
	for _, path := range paths {
		if !covered[path] {
			t.Errorf("%s changed no encoding under any of the %d sources, so nothing in this package writes it",
				path, len(sources))
		}
	}
	t.Logf("%d field paths swept over %d sources", len(paths), len(sources))
}

// TestTheLeafNodeFieldWalkReadsTheWholeStructure is the positive control on the derivation
// above. A walk that read nothing, or that stopped at the first delegated field, leaves the
// sweep asserting less while reporting exactly what a complete one reports.
func TestTheLeafNodeFieldWalkReadsTheWholeStructure(t *testing.T) {
	paths := leafNodeCodecFieldPaths(t)
	for _, name := range []string{
		"EncryptionKey", "SignatureKey", "Credential", "Capabilities",
		"LeafNodeSource", "Lifetime.NotBefore", "Lifetime.NotAfter",
		"ParentHash", "Extensions", "Signature",
	} {
		if !slices.Contains(paths, name) {
			t.Errorf("the field walk read %v, and LeafNode certainly has a %s", paths, name)
		}
	}
	// the walk descends into Lifetime and not into Credential, and that split is the type's
	// rather than a name's
	if leafNodeFieldIsDelegated(reflect.TypeOf(Lifetime{})) {
		t.Error("Lifetime reads as carrying a codec of its own, so the walk would stop above the two fields LeafNode writes itself")
	}
	for _, delegated := range []reflect.Type{reflect.TypeOf(Credential{}), reflect.TypeOf(Capabilities{})} {
		if !leafNodeFieldIsDelegated(delegated) {
			t.Errorf("%s reads as having no codec of its own, so the walk would descend into fields another file owns", delegated)
		}
	}
}

// ---------------------------------------------------------------------------
// the round trip, over every source
// ---------------------------------------------------------------------------

// decodedFormOf is what a decode of this leaf must produce: the same value with the variant
// fields the source does not carry left at their zero value.
//
// Derived from the same table the sweep above checks against the type, so a decoder that filled
// a field its source does not carry fails here without anybody writing a case for it.
func decodedFormOf(t *testing.T, leaf *LeafNode) *LeafNode {
	t.Helper()
	out := *leaf
	for source, paths := range leafNodeVariantPaths {
		if source == leaf.LeafNodeSource {
			continue
		}
		for _, path := range paths {
			field := leafNodeFieldAt(&out, path)
			field.Set(reflect.Zero(field.Type()))
		}
	}
	return &out
}

func sameLeafNode(a *LeafNode, b *LeafNode) bool {
	return reflect.DeepEqual(a, b)
}

func describeLeafNode(leaf *LeafNode) string {
	return fmt.Sprintf("source=%d enc=%x sig_key=%x credential=%+v capabilities=%+v lifetime=%+v parent_hash=%x extensions=%+v signature=%x",
		leaf.LeafNodeSource, leaf.EncryptionKey, leaf.SignatureKey, leaf.Credential,
		leaf.Capabilities, leaf.Lifetime, leaf.ParentHash, leaf.Extensions, leaf.Signature)
}

// TestLeafNodeRoundTripEverySource is the plan's round trip, over every source this package
// declares rather than the three it listed, and comparing the WHOLE decoded value rather than
// three of its nine fields.
//
// The plan's version compared the source, the parent hash and the lifetime, which leaves a
// codec that dropped the signature from both halves passing. DeepEqual against the expected
// decoded form is what closes that, and the expected form is derived from the variant table so
// a field decoded under a source that does not carry it fails as well.
func TestLeafNodeRoundTripEverySource(t *testing.T) {
	for _, source := range leafNodeSources(t) {
		in := testLeafNodeOfSource(source)
		encoded, err := syntax.Marshal(in)
		if err != nil {
			t.Fatalf("source %d: Marshal: %v", source, err)
		}
		out := &LeafNode{}
		if err := syntax.Unmarshal(encoded, out); err != nil {
			t.Fatalf("source %d: Unmarshal: %v", source, err)
		}
		if want := decodedFormOf(t, testLeafNodeOfSource(source)); !sameLeafNode(out, want) {
			t.Errorf("source %d: round trip gave\n %s\nwant\n %s", source, describeLeafNode(out), describeLeafNode(want))
		}
		reencoded, err := syntax.Marshal(out)
		if err != nil {
			t.Fatalf("source %d: re-Marshal: %v", source, err)
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Errorf("source %d: re-encode =\n %x\nwant\n %x", source, reencoded, encoded)
		}
	}
}

// ---------------------------------------------------------------------------
// the unknown source, refused by both halves
// ---------------------------------------------------------------------------

// TestLeafNodeRefusesEverySourceOutsideTheRegistry states the refusal over the class rather than
// over the one value the plan picked.
//
// A switch is a closed set and an octet is not: what has to hold is that every value the
// registry does not name is refused, on both halves, since a lenient decoder would have to guess
// how many octets the variant occupies and every guess accepts a second encoding of some other
// leaf.
func TestLeafNodeRefusesEverySourceOutsideTheRegistry(t *testing.T) {
	declared := leafNodeSources(t)
	refused := 0
	for candidate := 0; candidate <= 0xff; candidate += 1 {
		source := LeafNodeSource(candidate)
		if slices.Contains(declared, source) {
			continue
		}
		if _, err := syntax.Marshal(testLeafNodeOfSource(source)); !errors.Is(err, ErrTreeMalformed) {
			t.Fatalf("source %d: Marshal err = %v, want ErrTreeMalformed", source, err)
		}
		// the decode half, over an encoding whose source octet is the unknown one and whose
		// remaining bytes are a perfectly good update leaf
		encoded := bytes.Clone(handDerivedLeafNodeGolden(LeafNodeSourceUpdate))
		encoded[len(handDerivedLeafNodeCommon(LeafNodeSourceUpdate))-1] = byte(candidate)
		if err := syntax.Unmarshal(encoded, &LeafNode{}); !errors.Is(err, ErrTreeMalformed) {
			t.Fatalf("source %d: Unmarshal err = %v, want ErrTreeMalformed", source, err)
		}
		refused += 1
	}
	if want := 0x100 - len(declared); refused != want {
		t.Errorf("%d source octets were refused, and %d are outside the registry", refused, want)
	}
}

// TestLeafNodeRefusesTrailingBytes is the full consumption half. A decoder that ignores a tail
// accepts two encodings of one leaf, and the leaf's signature is taken over serialized bytes, so
// that is a signature bypass primitive rather than a leniency.
func TestLeafNodeRefusesTrailingBytes(t *testing.T) {
	for _, source := range leafNodeSources(t) {
		encoded := handDerivedLeafNodeGolden(source)
		for _, tail := range [][]byte{{0x00}, {0xff}, repeatByte(0x5a, 17)} {
			longer := joinBytes(encoded, tail)
			if err := syntax.Unmarshal(longer, &LeafNode{}); !errors.Is(err, syntax.ErrTrailingBytes) {
				t.Errorf("source %d with %d trailing octets: err = %v, want ErrTrailingBytes", source, len(tail), err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// the truncation and corruption sweeps, derived over the encoding's length
// ---------------------------------------------------------------------------

// TestLeafNodeRefusesEveryTruncation runs over every prefix of every source's encoding rather
// than over the field boundaries somebody thought of, which is the same reason the field class
// above is derived: the boundaries a codec actually has are the ones a sweep over the length
// finds, and a prefix that decoded would be a leaf accepted out of fewer bytes than it takes to
// state one.
func TestTheLeafNodeTruncationSweepRefusesEveryPrefix(t *testing.T) {
	for _, source := range leafNodeSources(t) {
		encoded := handDerivedLeafNodeGolden(source)
		for cut := 0; cut < len(encoded); cut += 1 {
			leaf := &LeafNode{}
			err := func() (err error) {
				defer func() {
					if raised := recover(); raised != nil {
						err = fmt.Errorf("panicked: %v", raised)
						t.Errorf("source %d: decoding the first %d of %d octets panicked with %v",
							source, cut, len(encoded), raised)
					}
				}()
				return syntax.Unmarshal(encoded[:cut], leaf)
			}()
			if err == nil {
				t.Errorf("source %d: the first %d of %d octets decoded to %s",
					source, cut, len(encoded), describeLeafNode(leaf))
			}
		}
	}
}

// TestEveryOctetOfALeafNodeEncodingIsLoadBearing is the corruption half, and it is stated as
// what canonicality means rather than as "the decode fails".
//
// Altering an octet must either be refused or produce a leaf that re-encodes to the ALTERED
// bytes. A decoder that skipped a field, read a field it did not write back, or wrote a constant
// where it should have written what it read, produces the third outcome: the altered input
// decodes and re-encodes to the original, which is two encodings of one value and a second
// spelling of every signed structure that carries a leaf.
func TestEveryOctetOfALeafNodeEncodingIsLoadBearing(t *testing.T) {
	for _, source := range leafNodeSources(t) {
		encoded := handDerivedLeafNodeGolden(source)
		refused, carried := 0, 0
		for at := 0; at < len(encoded); at += 1 {
			altered := bytes.Clone(encoded)
			altered[at] ^= 0xff
			decoded := &LeafNode{}
			if err := syntax.Unmarshal(altered, decoded); err != nil {
				refused += 1
				continue
			}
			reencoded, err := syntax.Marshal(decoded)
			if err != nil {
				t.Errorf("source %d: octet %d altered decoded and then failed to re-encode: %v", source, at, err)
				continue
			}
			if !bytes.Equal(reencoded, altered) {
				t.Errorf("source %d: octet %d altered decoded to a leaf that re-encodes to\n %x\nrather than to the bytes it was read from\n %x",
					source, at, reencoded, altered)
				continue
			}
			carried += 1
		}
		if refused+carried != len(encoded) {
			t.Errorf("source %d: the sweep accounted for %d of %d octets", source, refused+carried, len(encoded))
		}
		t.Logf("source %d: %d of %d altered octets refused, %d carried through the round trip", source, refused, len(encoded), carried)
	}
}

// ---------------------------------------------------------------------------
// the field assignment cross check against the vendored vectors
// ---------------------------------------------------------------------------

// upstreamLeafNode is one leaf another implementation encoded, with the byte range of every
// field read out of the raw octets by a navigator that does not use this package's LeafNode.
//
// Reading the fields out as RANGES rather than decoding them is the whole point. A round trip
// against upstream bytes cannot see a symmetric field swap -- the same swap on the way in and on
// the way out reproduces the octets exactly -- so what the swap is caught by is the assignment:
// upstream's first field is the encryption key, and a decoder that put those octets in
// SignatureKey disagrees with that whatever it re-encodes to.
type upstreamLeafNode struct {
	origin        string
	raw           []byte
	encryptionKey []byte
	signatureKey  []byte
	identity      []byte
	capabilities  []byte
	source        uint8
	notBefore     uint64
	notAfter      uint64
	parentHash    []byte
	extensions    []byte
	signature     []byte
}

// readUpstreamLeafNode consumes one section 7.2 LeafNode from r and returns its fields as
// ranges of raw, which must be the slice r was opened over. Only a BasicCredential is handled,
// which is every credential the vendored vectors carry and the only one this profile admits.
//
// Written from the RFC and using nothing of this package above syntax.Reader, which is the layer
// below and has published vectors of its own. A navigator built on the decoder it is here to
// check would agree with that decoder by construction.
func readUpstreamLeafNode(r *syntax.Reader, raw []byte) (upstreamLeafNode, bool) {
	leaf := upstreamLeafNode{}
	start := r.Offset()
	var err error
	if leaf.encryptionKey, err = r.ReadOpaque(); err != nil {
		return leaf, false
	}
	if leaf.signatureKey, err = r.ReadOpaque(); err != nil {
		return leaf, false
	}
	credentialType, err := r.ReadUint16()
	if err != nil || credentialType != uint16(CredentialTypeBasic) {
		return leaf, false
	}
	if leaf.identity, err = r.ReadOpaque(); err != nil {
		return leaf, false
	}
	capabilitiesAt := r.Offset()
	// the five registry vectors, taken as opaque regions so this reader never depends on the
	// decoder it is here to check
	for range 5 {
		if _, err := r.ReadOpaque(); err != nil {
			return leaf, false
		}
	}
	leaf.capabilities = raw[capabilitiesAt:r.Offset()]
	if leaf.source, err = r.ReadUint8(); err != nil {
		return leaf, false
	}
	switch leaf.source {
	case 1: // key_package: a Lifetime, which is two uint64 and carries no length prefix
		if leaf.notBefore, err = r.ReadUint64(); err != nil {
			return leaf, false
		}
		if leaf.notAfter, err = r.ReadUint64(); err != nil {
			return leaf, false
		}
	case 2: // update: nothing further
	case 3: // commit: parent_hash
		if leaf.parentHash, err = r.ReadOpaque(); err != nil {
			return leaf, false
		}
	default:
		return leaf, false
	}
	extensionsAt := r.Offset()
	if _, err := r.ReadOpaque(); err != nil {
		return leaf, false
	}
	leaf.extensions = raw[extensionsAt:r.Offset()]
	if leaf.signature, err = r.ReadOpaque(); err != nil {
		return leaf, false
	}
	leaf.raw = raw[start:r.Offset()]
	return leaf, true
}

// upstreamLeafNodesOfRatchetTree reads blob as a ratchet_tree extension body and returns every
// leaf in it. A blob that is not one yields nothing rather than an error, because every string
// in every vector file is tried.
func upstreamLeafNodesOfRatchetTree(blob []byte) []upstreamLeafNode {
	outer := syntax.NewReader(blob)
	nodes, err := outer.ReadOpaque()
	if err != nil || outer.Done() != nil {
		return nil
	}
	r := syntax.NewReader(nodes)
	found := []upstreamLeafNode{}
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
			leaf, ok := readUpstreamLeafNode(r, nodes)
			if !ok {
				return nil
			}
			found = append(found, leaf)
		case 2:
			// ParentNode: encryption_key, parent_hash, unmerged_leaves, all opaque<V> as far
			// as this walk is concerned
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

// upstreamLeafNodes is every distinct LeafNode encoding the vendored mlswg vectors contain.
//
// The selection is strict parsing rather than a list of upstream's field names, for the reason
// rule 5 gives: a name list is a claim about somebody else's spelling, and exact region
// consumption with a recognised credential type and a recognised source is what separates a leaf
// from a blob without one.
func upstreamLeafNodes(t *testing.T) map[string]upstreamLeafNode {
	t.Helper()
	found := map[string]upstreamLeafNode{}
	read := 0
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
			leaves := upstreamLeafNodesOfRatchetTree(blob)
			// a bare LeafNode, which is what an Update proposal's body is
			r := syntax.NewReader(blob)
			if leaf, ok := readUpstreamLeafNode(r, blob); ok && r.Done() == nil {
				leaves = append(leaves, leaf)
			}
			for _, leaf := range leaves {
				leaf.origin = path
				read += 1
				found[hex.EncodeToString(leaf.raw)] = leaf
			}
		}
	}
	if read == 0 {
		t.Fatal("no leaf node was read out of the vendored vectors, so every upstream comparison below is against an empty set")
	}
	t.Logf("%d upstream leaf nodes read, %d distinct encodings", read, len(found))
	return found
}

// TestLeafNodeAssignsEveryFieldTheUpstreamVectorsPutWhereItIs is the one property in this file
// that reaches a symmetric field order swap over real bytes.
//
// Every leaf another implementation wrote is decoded here and each Go field is compared against
// the byte range an independent navigator says that field occupies. A codec that swapped two
// fields in both halves round trips byte exact against these same octets and fails here, naming
// the field it put in the wrong place.
func TestLeafNodeAssignsEveryFieldTheUpstreamVectorsPutWhereItIs(t *testing.T) {
	upstream := upstreamLeafNodes(t)
	if len(upstream) < 2 {
		t.Fatalf("the vendored vectors yielded %d distinct leaf encodings; a single one cannot show that two fields are read the same way twice",
			len(upstream))
	}
	sources := map[uint8]int{}
	for _, name := range slices.Sorted(maps.Keys(upstream)) {
		leaf := upstream[name]
		sources[leaf.source] += 1
		decoded := &LeafNode{}
		if err := syntax.Unmarshal(leaf.raw, decoded); err != nil {
			t.Errorf("%s from %s: Unmarshal: %v", name[:16], leaf.origin, err)
			continue
		}
		if !bytes.Equal(decoded.EncryptionKey, leaf.encryptionKey) {
			t.Errorf("%s: EncryptionKey = %x, and the first field of those octets is %x",
				name[:16], decoded.EncryptionKey, leaf.encryptionKey)
		}
		if !bytes.Equal(decoded.SignatureKey, leaf.signatureKey) {
			t.Errorf("%s: SignatureKey = %x, and the second field of those octets is %x",
				name[:16], decoded.SignatureKey, leaf.signatureKey)
		}
		if decoded.Credential.CredentialType != CredentialTypeBasic || !bytes.Equal(decoded.Credential.Identity, leaf.identity) {
			t.Errorf("%s: Credential = %+v, and those octets carry a basic credential of %x",
				name[:16], decoded.Credential, leaf.identity)
		}
		capabilities, err := syntax.Marshal(&decoded.Capabilities)
		if err != nil {
			t.Errorf("%s: Marshal the decoded capabilities: %v", name[:16], err)
		} else if !bytes.Equal(capabilities, leaf.capabilities) {
			t.Errorf("%s: the decoded capabilities re-encode to %x, and those octets are %x",
				name[:16], capabilities, leaf.capabilities)
		}
		if uint8(decoded.LeafNodeSource) != leaf.source {
			t.Errorf("%s: LeafNodeSource = %d, and that octet is %d", name[:16], decoded.LeafNodeSource, leaf.source)
		}
		if decoded.Lifetime.NotBefore != leaf.notBefore || decoded.Lifetime.NotAfter != leaf.notAfter {
			t.Errorf("%s: Lifetime = %+v, and those octets carry {%d %d}",
				name[:16], decoded.Lifetime, leaf.notBefore, leaf.notAfter)
		}
		if !bytes.Equal(decoded.ParentHash, leaf.parentHash) {
			t.Errorf("%s: ParentHash = %x, and those octets carry %x", name[:16], decoded.ParentHash, leaf.parentHash)
		}
		w := syntax.NewWriter()
		if err := WriteExtensions(w, decoded.Extensions); err != nil {
			t.Errorf("%s: WriteExtensions: %v", name[:16], err)
		} else if extensions, err := w.Bytes(); err != nil {
			t.Errorf("%s: the re-encoded extensions: %v", name[:16], err)
		} else if !bytes.Equal(extensions, leaf.extensions) {
			t.Errorf("%s: the decoded extensions re-encode to %x, and those octets are %x",
				name[:16], extensions, leaf.extensions)
		}
		if !bytes.Equal(decoded.Signature, leaf.signature) {
			t.Errorf("%s: Signature = %x, and the last field of those octets is %x",
				name[:16], decoded.Signature, leaf.signature)
		}
		reencoded, err := syntax.Marshal(decoded)
		if err != nil {
			t.Errorf("%s: re-Marshal: %v", name[:16], err)
			continue
		}
		if !bytes.Equal(reencoded, leaf.raw) {
			t.Errorf("%s: re-encode =\n %x\nwant\n %x", name[:16], reencoded, leaf.raw)
		}
	}
	if len(sources) < 2 {
		t.Errorf("every upstream leaf carried source %v, so the variant this comparison is worth most for was never reached", sources)
	}
	t.Logf("upstream leaf sources: %v", sources)
}

// ---------------------------------------------------------------------------
// Clone
// ---------------------------------------------------------------------------

// TestLeafNodeCloneSharesNoStorageAtAnyDepth walks the structure rather than checking the three
// fields the plan's version named.
//
// A deep copy that stops one level short is indistinguishable from a complete one until
// something writes through the level it missed, and a copy that missed the signature or the
// encryption key is the same defect as one that missed the parent hash. The walk finds every
// slice at every depth off the type, writes through the clone's copy of it, and reads the
// original back -- so a field added to LeafNode later is covered without anybody editing this.
func TestLeafNodeCloneSharesNoStorageAtAnyDepth(t *testing.T) {
	for _, source := range leafNodeSources(t) {
		original := testLeafNodeOfSource(source)
		reference := testLeafNodeOfSource(source)
		clone := original.Clone()
		if !sameLeafNode(clone, reference) {
			t.Fatalf("source %d: Clone gave\n %s\nwant\n %s", source, describeLeafNode(clone), describeLeafNode(reference))
		}
		written := writeThroughEverySlice(reflect.ValueOf(clone).Elem(), "")
		if len(written) == 0 {
			t.Fatalf("source %d: the walk wrote through no slice, so this observed nothing", source)
		}
		if sameLeafNode(original, reference) {
			t.Logf("source %d: %d slices written through, none reached the original", source, len(written))
			continue
		}
		t.Errorf("source %d: writing through %v on the clone changed the original to\n %s",
			source, written, describeLeafNode(original))
	}
}

// writeThroughEverySlice writes a distinguishable octet into every slice element reachable from
// v, at every depth, and returns the paths it wrote. A slice the walk cannot write into -- an
// empty one -- is grown first, since a clone that shared a nil header shares nothing and a clone
// that shared an empty one has nothing to observe.
func writeThroughEverySlice(v reflect.Value, prefix string) []string {
	written := []string{}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i += 1 {
			written = append(written, writeThroughEverySlice(v.Field(i), prefix+"."+v.Type().Field(i).Name)...)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i += 1 {
			written = append(written, writeThroughEverySlice(v.Index(i), fmt.Sprintf("%s[%d]", prefix, i))...)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(v.Uint() ^ 0xff)
		written = append(written, prefix)
	}
	return written
}

// TestTheCloneWalkCanSeeASharedArray is the positive control on the walk above. A walk that
// wrote nowhere, or that stopped at the first level, reports the clean run a complete one
// reports, so it is run against a shallow copy known to share every slice it has.
func TestTheCloneWalkCanSeeASharedArray(t *testing.T) {
	for _, source := range leafNodeSources(t) {
		original := testLeafNodeOfSource(source)
		shallow := *original
		written := writeThroughEverySlice(reflect.ValueOf(&shallow).Elem(), "")
		if len(written) == 0 {
			t.Fatalf("source %d: the walk wrote through nothing", source)
		}
		if sameLeafNode(original, testLeafNodeOfSource(source)) {
			t.Errorf("source %d: a shallow copy was written through at %v and the original is unchanged, so this walk cannot see a shared array",
				source, written)
		}
	}
}

// TestTheCloneWalkReachesEverySliceOfTheStructure states the walk's coverage against the type,
// since a walk that reached three of the eight slices would pass the control above.
func TestTheCloneWalkReachesEverySliceOfTheStructure(t *testing.T) {
	leaf := testLeafNodeOfSource(LeafNodeSourceCommit)
	written := writeThroughEverySlice(reflect.ValueOf(leaf).Elem(), "")
	for _, want := range []string{
		".EncryptionKey[0]", ".SignatureKey[0]", ".Credential.Identity[0]",
		".Capabilities.Versions[0]", ".Capabilities.CipherSuites[0]",
		".Capabilities.Extensions[0]", ".Capabilities.Credentials[0]",
		".ParentHash[0]", ".Extensions[0].ExtensionData[0]", ".Signature[0]",
	} {
		if !slices.Contains(written, want) {
			t.Errorf("the clone walk wrote %v and did not reach %s", written, want)
		}
	}
}
