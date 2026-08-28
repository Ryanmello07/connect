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
	"time"

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
// the decoded leaf is a function of its bytes and of nothing the receiver held
// ---------------------------------------------------------------------------

// leafNodePriorContents is every state a receiver can arrive in that this file can build: the
// zero leaf, and a leaf of every source the package declares.
//
// Derived over the source class rather than over the one prior somebody picks, because the
// failure this is about is per PAIR -- only a receiver that already held a source carrying a
// variant field can leave that field standing under a source that does not carry it, and which
// pairs those are is the variant table's business rather than a test author's guess.
func leafNodePriorContents(t *testing.T) []*LeafNode {
	t.Helper()
	priors := []*LeafNode{{}}
	for _, source := range leafNodeSources(t) {
		priors = append(priors, testLeafNodeOfSource(source))
	}
	return priors
}

// TestALeafNodeDecodesToTheSameValueWhateverItsReceiverHeld is the property every comparison of
// two leaves in this package rests on, and it is not a round trip property.
//
// The variant arms of the decoder assign only the field their own source carries, so a decoder
// that writes through its receiver as it reads leaves the PREVIOUS leaf's ParentHash or Lifetime
// standing under a source that does not carry it. The bytes are unaffected -- the stale field is
// not written under the new source -- so the encoding round trips, re-encodes byte exact, and
// agrees with every golden in this file. What it disagrees with is the same bytes decoded into a
// fresh receiver, and that is a leaf comparing unequal to itself depending on where it was
// decoded.
func TestALeafNodeDecodesToTheSameValueWhateverItsReceiverHeld(t *testing.T) {
	priors := leafNodePriorContents(t)
	for _, source := range leafNodeSources(t) {
		encoded := handDerivedLeafNodeGolden(source)
		fresh := &LeafNode{}
		if err := syntax.Unmarshal(encoded, fresh); err != nil {
			t.Fatalf("source %d: Unmarshal into a fresh receiver: %v", source, err)
		}
		for at, prior := range priors {
			reused := prior.Clone()
			if err := syntax.Unmarshal(encoded, reused); err != nil {
				t.Fatalf("source %d: Unmarshal into a receiver holding prior %d: %v", source, at, err)
			}
			if !sameLeafNode(reused, fresh) {
				t.Errorf("source %d: decoding into a receiver that held\n %s\ngave a leaf differing at %v from the same bytes decoded fresh:\n %s\nwant\n %s",
					source, describeLeafNode(prior), leafNodeLocationsDifferingBetween(reused, fresh),
					describeLeafNode(reused), describeLeafNode(fresh))
			}
		}
	}
	t.Logf("%d prior receiver contents over %d sources", len(priors), len(leafNodeSources(t)))
}

// leafNodeRefusedEncodingsOf is every input this file can build that a decode of one source's
// leaf must refuse: every proper prefix of that source's encoding, and that encoding under every
// source octet the registry does not name.
//
// Derived over the length and over the octet rather than written as the field boundaries
// somebody thought of, for the same reason the truncation sweep below is: the boundaries this
// codec actually has are the ones a sweep over the length finds, and every one of them is a
// place a decode can stop half way through the receiver.
func leafNodeRefusedEncodingsOf(t *testing.T, source LeafNodeSource) [][]byte {
	t.Helper()
	declared := leafNodeSources(t)
	encoded := handDerivedLeafNodeGolden(source)
	inputs := [][]byte{}
	for cut := 0; cut < len(encoded); cut += 1 {
		inputs = append(inputs, encoded[:cut])
	}
	for candidate := 0; candidate <= 0xff; candidate += 1 {
		if slices.Contains(declared, LeafNodeSource(candidate)) {
			continue
		}
		altered := bytes.Clone(encoded)
		altered[len(handDerivedLeafNodeCommon(source))-1] = byte(candidate)
		inputs = append(inputs, altered)
	}
	return inputs
}

// TestARefusedLeafNodeDecodeLeavesItsReceiverUntouched is the discipline Credential.UnmarshalMLS
// already keeps, stated for the leaf as well so the two decoders of this commit do not disagree
// about it with only one of them tested.
//
// Credential refuses the credential type before it reads the identity, so no certificate chain
// is ever allocated on this package's behalf, and credential_test.go asserts it. A leaf decoder
// that wrote its fields as it read them would leave a receiver holding an encryption key, a
// signature key and a source octet out of a leaf this package REFUSED -- which is a value that
// never existed anywhere, assembled out of half of somebody else's bytes, sitting in a variable
// the caller may well reuse. Nothing about the refusal tells the caller that happened.
func TestARefusedLeafNodeDecodeLeavesItsReceiverUntouched(t *testing.T) {
	priors := leafNodePriorContents(t)
	refused, accepted := 0, 0
	for _, source := range leafNodeSources(t) {
		for _, input := range leafNodeRefusedEncodingsOf(t, source) {
			for _, prior := range priors {
				held := prior.Clone()
				before := prior.Clone()
				if err := syntax.Unmarshal(input, held); err == nil {
					accepted += 1
					continue
				}
				refused += 1
				if sameLeafNode(held, before) {
					continue
				}
				// one report is the whole statement: there are thousands of refusals here
				// and a receiver written through by any of them is the same defect
				t.Errorf("source %d: a refused decode of %d octets into a receiver that held\n %s\nwrote through it at %v, leaving\n %s",
					source, len(input), describeLeafNode(before),
					leafNodeLocationsDifferingBetween(held, before), describeLeafNode(held))
				return
			}
		}
	}
	if accepted != 0 {
		t.Errorf("%d of the inputs this sweep built decoded rather than being refused, so the property above was never stated over them", accepted)
	}
	if refused == 0 {
		t.Fatal("no input was refused, so this observed nothing")
	}
	t.Logf("%d refused decodes over %d prior receiver contents left the receiver exactly as they found it", refused, len(priors))
}

// ---------------------------------------------------------------------------
// a nil vector and an empty one are one leaf
// ---------------------------------------------------------------------------

// leafNodeVectorPaths is every variable length field the leaf's encoding carries, derived off
// the type: it descends into the structures LeafNode holds by value and stops AT the vector,
// since an element of a vector is not a field of the leaf.
//
// Derived rather than listed, and the finding that produced this test is exactly what a list
// costs: the nil versus empty asymmetry was disclosed for Capabilities and not for Extensions,
// which carries it too, because a disclosure is written from the fields somebody had in mind.
func leafNodeVectorPaths(t *testing.T) []string {
	t.Helper()
	paths := leafNodeVectorPathsOf(reflect.TypeOf(LeafNode{}), "")
	if len(paths) == 0 {
		t.Fatal("the type walk found no vector on LeafNode, so the sweep below runs over nothing")
	}
	return paths
}

func leafNodeVectorPathsOf(valueType reflect.Type, prefix string) []string {
	switch valueType.Kind() {
	case reflect.Struct:
		paths := []string{}
		for i := 0; i < valueType.NumField(); i += 1 {
			name := valueType.Field(i).Name
			if prefix != "" {
				name = prefix + "." + name
			}
			paths = append(paths, leafNodeVectorPathsOf(valueType.Field(i).Type, name)...)
		}
		return paths
	case reflect.Slice:
		return []string{prefix}
	default:
		return nil
	}
}

// TestANilVectorAndAnEmptyOneAreOneLeafOnTheWire states the asymmetry rather than leaving it to
// be rediscovered, over every vector of the structure rather than the one the builder disclosed.
//
// The wire has ONE spelling for a zero length vector, and Go has two values that produce it. So
// a leaf built by hand with a nil vector encodes exactly like the same leaf with an empty one,
// and the decode of those bytes answers the empty one -- syntax.ReadOpaque allocates and
// syntax.ReadVector allocates, and neither ever answers nil. The consequence is that a hand
// built leaf carrying a nil does not survive a round trip under reflect.DeepEqual even though
// its ENCODING does, which is a trap for every later task that compares two leaves as values:
// one off the wire and one built in a test are unequal for a reason neither the bytes nor the
// protocol knows about.
//
// Both directions are asserted, so this is a pin and not a floor. If the codec is ever changed
// to answer nil for an absent vector, this fails, and the comment on LeafNode that describes the
// asymmetry has to be changed in the same commit.
func TestANilVectorAndAnEmptyOneAreOneLeafOnTheWire(t *testing.T) {
	paths := leafNodeVectorPaths(t)
	variant := map[string]LeafNodeSource{}
	for source, named := range leafNodeVariantPaths {
		for _, path := range named {
			variant[path] = source
		}
	}
	for _, source := range leafNodeSources(t) {
		for _, path := range paths {
			withNil := testLeafNodeOfSource(source)
			nilField := leafNodeFieldAt(withNil, path)
			nilField.Set(reflect.Zero(nilField.Type()))
			withEmpty := testLeafNodeOfSource(source)
			emptyField := leafNodeFieldAt(withEmpty, path)
			emptyField.Set(reflect.MakeSlice(emptyField.Type(), 0, 0))

			nilBytes, err := syntax.Marshal(withNil)
			if err != nil {
				t.Fatalf("source %d: Marshal with %s nil: %v", source, path, err)
			}
			emptyBytes, err := syntax.Marshal(withEmpty)
			if err != nil {
				t.Fatalf("source %d: Marshal with %s empty: %v", source, path, err)
			}
			if !bytes.Equal(nilBytes, emptyBytes) {
				t.Errorf("source %d: %s nil encodes to\n %x\nand %s empty encodes to\n %x; the wire has one spelling for a zero length vector and this codec has two",
					source, path, nilBytes, path, emptyBytes)
				continue
			}
			fromNil, fromEmpty := &LeafNode{}, &LeafNode{}
			if err := syntax.Unmarshal(nilBytes, fromNil); err != nil {
				t.Fatalf("source %d: Unmarshal the %s nil encoding: %v", source, path, err)
			}
			if err := syntax.Unmarshal(emptyBytes, fromEmpty); err != nil {
				t.Fatalf("source %d: Unmarshal the %s empty encoding: %v", source, path, err)
			}
			if !sameLeafNode(fromNil, fromEmpty) {
				t.Errorf("source %d: %s: one encoding decoded to two leaves differing at %v, so the decode is reading something besides its bytes",
					source, path, leafNodeLocationsDifferingBetween(fromNil, fromEmpty))
				continue
			}
			decoded := leafNodeFieldAt(fromNil, path)
			carried := true
			if owner, isVariant := variant[path]; isVariant {
				carried = owner == source
			}
			if !carried {
				if !decoded.IsNil() {
					t.Errorf("source %d: %s is a variant field this source does not carry and the decode answered a non nil vector of %d, so it is not left at its zero value",
						source, path, decoded.Len())
				}
				continue
			}
			if decoded.IsNil() || decoded.Len() != 0 {
				t.Errorf("source %d: %s was encoded as a zero length vector and decoded to nil=%v len=%d, want a non nil empty one",
					source, path, decoded.IsNil(), decoded.Len())
				continue
			}
			if !sameLeafNode(fromEmpty, decodedFormOf(t, withEmpty)) {
				t.Errorf("source %d: the leaf carrying an empty %s did not survive its own round trip, differing at %v",
					source, path, leafNodeLocationsDifferingBetween(fromEmpty, decodedFormOf(t, withEmpty)))
			}
			if sameLeafNode(fromNil, decodedFormOf(t, withNil)) {
				t.Errorf("source %d: a leaf carrying a nil %s now round trips to a value equal to what went in, so the asymmetry disclosed on LeafNode is gone and that comment is stale",
					source, path)
			}
		}
	}
	t.Logf("%d vectors swept over %d sources", len(paths), len(leafNodeSources(t)))
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

// upstreamLeafNodeFloor is how many distinct leaf encodings the PINNED corpus yields, less a
// margin, and it is the only coverage claim the comparison below is able to make about how much
// of that corpus it actually read.
//
// A floor is stated at all because "more than one encoding" is not one. The leaves this reads
// come from two shapes -- the ratchet_tree extension bodies, which the treekem and passive
// client families carry in bulk, and the bare LeafNode an Update proposal's body is -- and a
// re-vendor that dropped the ratchet tree families would leave the comparison passing on a
// handful of Update leaves while reading none of the trees. That is the degradation a floor
// catches and a "more than one" does not.
//
// It is a number rather than a derivation because there is nothing here to derive it from: the
// corpus is somebody else's, and what makes the number safe is that it is pinned by digest in
// vectors_pin_test.go, so it moves only in a commit that changes VECTORS.sha256. This number
// moving in that same commit is the point of it. The margin is for the reader half rather than
// the corpus half -- a stricter parse that recognises fewer blobs is a change to this file and
// should be visible here without being brittle about single leaves.
//
// Measured: 2689 leaves read, 2528 distinct encodings, sources {1: 931, 2: 301, 3: 1296}.
const upstreamLeafNodeFloor = 2400

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
	if len(found) < upstreamLeafNodeFloor {
		t.Fatalf("%d distinct leaf encodings were read out of the pinned corpus and the floor is %d; either a family this reads from is gone from testdata, or the reader above stopped recognising one, and both leave every comparison below passing on whatever is left",
			len(found), upstreamLeafNodeFloor)
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
	// every source the package DECLARES, not two of however many there are. The variant is
	// what this comparison is worth most for -- a Lifetime read where a parent hash sits is
	// only visible on a leaf that carries one -- so a source with no upstream leaf behind it
	// is a source whose field assignment nothing here checked. Derived off the constants, so a
	// fourth source declared later is owed a vector on the commit that declares it.
	for _, declared := range leafNodeSources(t) {
		if sources[uint8(declared)] == 0 {
			t.Errorf("no upstream leaf carried source %d; the corpus yielded %v, so the fields that source carries were never compared against anybody else's bytes",
				declared, sources)
		}
	}
	t.Logf("upstream leaf sources: %v", sources)
}

// ---------------------------------------------------------------------------
// Clone
// ---------------------------------------------------------------------------

// testLeafNodeOfSourceWithEveryVectorOccupied is the template under one source with no empty
// vector left anywhere in it, which is the value every clone property below is stated over.
//
// An empty vector cannot show that a clone shares storage, and that is a fact about empty
// slices rather than about this codec: an empty header has no array behind it, so a Clone that
// assigned the field straight across shares nothing observable, appending to the copy allocates
// a new array, and no amount of writing through it reaches the original. The emptiness has to
// be gone BEFORE the clone is taken.
//
// It is grown here rather than filled in the template because the template's one empty vector
// is Capabilities.Proposals and it is empty on purpose -- an empty vector in the middle of the
// five is what separates their order in the hand derived golden, and a template that filled it
// would leave the five capability vectors interchangeable. Both properties are kept by growing
// a copy.
func testLeafNodeOfSourceWithEveryVectorOccupied(t *testing.T, source LeafNodeSource) *LeafNode {
	t.Helper()
	leaf := testLeafNodeOfSource(source)
	growEveryEmptySlice(reflect.ValueOf(leaf).Elem(), "")
	// the grower's own control, stated as the property rather than as the name of the field
	// that happens to be empty today: a second pass has nothing left to grow.
	if again := growEveryEmptySlice(reflect.ValueOf(leaf).Elem(), ""); len(again) != 0 {
		t.Fatalf("source %d: growing twice grew %v the second time, so the first pass left an empty vector behind and a clone sharing it would be unobservable",
			source, again)
	}
	return leaf
}

// growEveryEmptySlice puts one zero element into every empty slice reachable from v, at every
// depth, and answers the paths it grew.
//
// Derived off the value rather than told which field to grow, so a field added to LeafNode
// later that is empty in the template is occupied by the commit that adds it rather than on the
// day somebody notices. It grows nil slices too: a nil header and an empty one are equally
// unobservable, and which of the two a field holds is the template's business.
func growEveryEmptySlice(v reflect.Value, prefix string) []string {
	grown := []string{}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i += 1 {
			grown = append(grown, growEveryEmptySlice(v.Field(i), prefix+"."+v.Type().Field(i).Name)...)
		}
	case reflect.Slice:
		if v.Len() == 0 {
			v.Set(reflect.Append(v, reflect.Zero(v.Type().Elem())))
			grown = append(grown, prefix)
		}
		for i := 0; i < v.Len(); i += 1 {
			grown = append(grown, growEveryEmptySlice(v.Index(i), fmt.Sprintf("%s[%d]", prefix, i))...)
		}
	}
	return grown
}

// TestLeafNodeCloneSharesNoStorageAtAnyDepth walks the structure rather than checking the three
// fields the plan's version named.
//
// A deep copy that stops one level short is indistinguishable from a complete one until
// something writes through the level it missed, and a copy that missed the signature or the
// encryption key is the same defect as one that missed the parent hash. The walk finds every
// slice at every depth off the type, writes through the clone's copy of it, and reads the
// original back -- so a field added to LeafNode later is covered without anybody editing this.
//
// Over a leaf with every vector occupied, because a vector that is empty in the template is one
// this cannot observe at all: Clone sharing Capabilities.Proposals survived the whole suite
// while that was the value under test.
func TestLeafNodeCloneSharesNoStorageAtAnyDepth(t *testing.T) {
	for _, source := range leafNodeSources(t) {
		original := testLeafNodeOfSourceWithEveryVectorOccupied(t, source)
		reference := testLeafNodeOfSourceWithEveryVectorOccupied(t, source)
		clone := original.Clone()
		if !sameLeafNode(clone, reference) {
			t.Fatalf("source %d: Clone gave\n %s\nwant\n %s", source, describeLeafNode(clone), describeLeafNode(reference))
		}
		written := writeThroughEverySlice(reflect.ValueOf(clone).Elem(), "")
		if len(written) == 0 {
			t.Fatalf("source %d: the walk wrote through no slice, so this observed nothing", source)
		}
		if sameLeafNode(original, reference) {
			t.Logf("source %d: %d locations written through, none reached the original", source, len(written))
			continue
		}
		// the locations rather than the whole structure: what a reader needs is which field
		// Clone copied one level short, and a dump of a leaf with 176 scalars in it does not
		// say
		t.Errorf("source %d: writing through the clone reached the original at %v, so Clone shares that storage with the leaf it was made from",
			source, leafNodeLocationsDifferingBetween(original, reference))
	}
}

// leafNodeScalarsOf reads every scalar reachable from v, by the same path spelling the walk
// above writes, so that two leaves can be compared location by location.
func leafNodeScalarsOf(v reflect.Value, prefix string) map[string]uint64 {
	scalars := map[string]uint64{}
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i += 1 {
			maps.Copy(scalars, leafNodeScalarsOf(v.Field(i), prefix+"."+v.Type().Field(i).Name))
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i += 1 {
			maps.Copy(scalars, leafNodeScalarsOf(v.Index(i), fmt.Sprintf("%s[%d]", prefix, i)))
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		scalars[prefix] = v.Uint()
	}
	return scalars
}

// leafNodeLocationsDifferingBetween is where two leaves disagree, by path. A location present
// in one and not the other counts, since a vector that grew is a difference too.
func leafNodeLocationsDifferingBetween(a *LeafNode, b *LeafNode) []string {
	left := leafNodeScalarsOf(reflect.ValueOf(a).Elem(), "")
	right := leafNodeScalarsOf(reflect.ValueOf(b).Elem(), "")
	differing := []string{}
	for path, value := range left {
		if other, held := right[path]; !held || other != value {
			differing = append(differing, path)
		}
	}
	for path := range right {
		if _, held := left[path]; !held {
			differing = append(differing, path)
		}
	}
	slices.Sort(differing)
	return differing
}

// writeThroughEverySlice writes a distinguishable octet into every scalar reachable from v, at
// every depth, and returns the paths it wrote.
//
// It does NOT grow anything, and cannot: by the time it runs, the clone under test has already
// been made, and a slice grown on the copy allocates an array the original never had. Growing
// is testLeafNodeOfSourceWithEveryVectorOccupied's job and it happens before the clone.
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
		original := testLeafNodeOfSourceWithEveryVectorOccupied(t, source)
		shallow := *original
		written := writeThroughEverySlice(reflect.ValueOf(&shallow).Elem(), "")
		if len(written) == 0 {
			t.Fatalf("source %d: the walk wrote through nothing", source)
		}
		if sameLeafNode(original, testLeafNodeOfSourceWithEveryVectorOccupied(t, source)) {
			t.Errorf("source %d: a shallow copy was written through at %v and the original is unchanged, so this walk cannot see a shared array",
				source, written)
		}
	}
}

// leafNodeWritablePathsOf is every location a complete walk of a value of this type must reach,
// derived off the TYPE: every scalar the structure holds, and one element of every vector, at
// every depth.
//
// Derived and not listed, and this one is the rule 5 shape caught red handed. What this
// replaced was ten names typed out by hand, and the walk it was controlling reached nine of
// them: .Capabilities.Proposals[0] was absent from the walk AND from the list, because the
// template's Proposals is empty and nobody thinks of the case they did not think of. A list
// written from the same understanding as the code it controls reports exactly what a complete
// one reports.
//
// The paths use index 0 because the walk is run over a leaf whose every vector is occupied, so
// element zero exists in all of them; a vector with more elements is written through further
// and containment is the assertion rather than equality.
func leafNodeWritablePathsOf(valueType reflect.Type, prefix string) []string {
	switch valueType.Kind() {
	case reflect.Struct:
		paths := []string{}
		for i := 0; i < valueType.NumField(); i += 1 {
			paths = append(paths, leafNodeWritablePathsOf(valueType.Field(i).Type, prefix+"."+valueType.Field(i).Name)...)
		}
		return paths
	case reflect.Slice:
		return leafNodeWritablePathsOf(valueType.Elem(), prefix+"[0]")
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return []string{prefix}
	default:
		return nil
	}
}

// TestTheCloneWalkReachesEverySliceOfTheStructure states the walk's coverage against the type,
// since a walk that reached three of the eight vectors would pass the control above.
func TestTheCloneWalkReachesEverySliceOfTheStructure(t *testing.T) {
	want := leafNodeWritablePathsOf(reflect.TypeOf(LeafNode{}), "")
	if len(want) == 0 {
		t.Fatal("the type walk derived no writable location, so this control demands nothing of the value walk")
	}
	for _, source := range leafNodeSources(t) {
		leaf := testLeafNodeOfSourceWithEveryVectorOccupied(t, source)
		written := writeThroughEverySlice(reflect.ValueOf(leaf).Elem(), "")
		missed := []string{}
		for _, one := range want {
			if !slices.Contains(written, one) {
				missed = append(missed, one)
			}
		}
		if len(missed) != 0 {
			t.Errorf("source %d: the clone walk wrote %d locations and did not reach %v, which the type says are there; a location the walk cannot reach is one a shared array hides behind",
				source, len(written), missed)
		}
	}
	t.Logf("%d writable locations derived off the type: %v", len(want), want)
}

// ---------------------------------------------------------------------------
// LeafNodeTBS, signing and signature verification
// ---------------------------------------------------------------------------

// leafNodeTestSigner is one provider and one signature key pair, for the sweeps below.
//
// The provider draws from the process entropy source rather than a scripted one, deliberately:
// nothing here asserts a byte of the key, and a key pair that is different on every run is what
// keeps a signature test from being satisfied by a value somebody wrote down.
func leafNodeTestSigner(t *testing.T) (CryptoProvider, SignaturePrivateKey, SignaturePublicKey) {
	t.Helper()
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	return crypto, priv, pub
}

// leafNodeSignedUnder is the template leaf under one source, carrying the signer's public key
// and signed in the context it was handed.
func leafNodeSignedUnder(t *testing.T, crypto CryptoProvider, priv SignaturePrivateKey,
	pub SignaturePublicKey, source LeafNodeSource, groupId []byte, leafIndex LeafIndex) *LeafNode {
	t.Helper()
	leaf := testLeafNodeOfSource(source)
	leaf.SignatureKey = pub
	if err := leaf.Sign(crypto, priv, groupId, leafIndex); err != nil {
		t.Fatalf("source %d: Sign: %v", source, err)
	}
	return leaf
}

// leafNodeContextBoundSources is the RFC 9420 section 7.2 select's SECOND arm, written as the
// sources whose LeafNodeTBS carries the group id and the leaf index.
//
// It is a statement about the protocol and cannot be derived from the Go type, exactly as
// leafNodeVariantPaths is not -- and like that table it is checked against the derived source
// class rather than trusted, by TestEveryLeafNodeSourceIsEitherBoundToItsGroupAndPositionOrNot.
// A fourth source added later fails there rather than silently inheriting the unbound arm,
// which is the arm that verifies anywhere.
var leafNodeContextBoundSources = map[LeafNodeSource]bool{
	LeafNodeSourceKeyPackage: false,
	LeafNodeSourceUpdate:     true,
	LeafNodeSourceCommit:     true,
}

// TestEveryLeafNodeSourceIsEitherBoundToItsGroupAndPositionOrNot holds the table above to the
// package's own constants, in both directions, so neither half can go stale in silence.
func TestEveryLeafNodeSourceIsEitherBoundToItsGroupAndPositionOrNot(t *testing.T) {
	sources := leafNodeSources(t)
	if got := slices.Sorted(maps.Keys(leafNodeContextBoundSources)); !slices.Equal(got, sources) {
		t.Fatalf("leafNodeContextBoundSources names sources %v and this package declares %v; a source with no row inherits whichever arm the switch falls through to, and one of the two verifies in any group at any position",
			got, sources)
	}
	// and the table is not all of one answer, or every sweep reading it asserts one arm
	bound, unbound := 0, 0
	for _, source := range sources {
		if leafNodeContextBoundSources[source] {
			bound += 1
			continue
		}
		unbound += 1
	}
	if bound == 0 || unbound == 0 {
		t.Fatalf("the table reads %d bound and %d unbound sources; the section 7.2 select has both arms and a table with one is one no sweep can tell apart from a switch that ignores the source",
			bound, unbound)
	}
}

// ---------------------------------------------------------------------------
// the hand derived LeafNodeTBS
// ---------------------------------------------------------------------------

// handDerivedLeafNodeExtensions is the extensions<V> field alone, which is where the TBS ends
// and the wire form goes on to the signature:
//
//	extensions<V>  one entry: f002 + 01 "k" = 4 octets -> 04 f002 016b   5
//
// It is split out of handDerivedLeafNodeTail rather than written twice, and
// TestTheHandDerivedTailIsItsExtensionsFollowedByItsSignature holds the split to the whole.
func handDerivedLeafNodeExtensions() []byte {
	return joinBytes([]byte{0x04}, []byte{0xf0, 0x02}, []byte{0x01}, []byte("k"))
}

// handDerivedLeafNodeTbs is the RFC 9420 section 7.2 LeafNodeTBS for the template leaf, written
// out from the RFC rather than read back through signatureContent:
//
//	the common prefix                            88
//	the variant the source selects        0 | 16 | 33
//	extensions<V>                                 5
//	then, for update and commit only:
//	  group_id<V>            n octets -> prefix + n
//	  leaf_index             uint32   ->          4
//
// The group id is length prefixed and the leaf index is NOT: the structure fixes the index at
// four octets and leaves the group id variable, so the prefix is the thing that separates a
// group id ending where the index begins from one an octet longer. The index is written big
// endian, which is the presentation language's only integer order.
//
// This is the statement of the preimage that owes nothing to this package's encoder. A field
// order swapped in signatureContent, an index written as a uint16, a group id written raw and a
// context appended under key_package are each invisible to signing and verifying against this
// implementation, and each moves these bytes.
func handDerivedLeafNodeTbs(source LeafNodeSource, groupId []byte, leafIndex LeafIndex) []byte {
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
	context := []byte{}
	if leafNodeContextBoundSources[source] {
		// the section 2.1.2 vector header, written out for the two widths this test reaches:
		// 0..63 octets is one octet, 64..16383 is two with the top bits 01
		prefix := []byte{byte(len(groupId))}
		if len(groupId) >= 0x40 {
			prefix = []byte{byte(0x40 | len(groupId)>>8), byte(len(groupId))}
		}
		context = joinBytes(prefix, groupId, []byte{
			byte(leafIndex >> 24), byte(leafIndex >> 16), byte(leafIndex >> 8), byte(leafIndex),
		})
	}
	return joinBytes(handDerivedLeafNodeCommon(source), variant,
		handDerivedLeafNodeExtensions(), context)
}

// TestTheHandDerivedTailIsItsExtensionsFollowedByItsSignature holds the split above to the
// whole it was cut out of. Two derivations of one field drift, and a split taken one octet out
// would make the TBS golden below compare against bytes neither the RFC nor this file states.
func TestTheHandDerivedTailIsItsExtensionsFollowedByItsSignature(t *testing.T) {
	want := joinBytes(handDerivedLeafNodeExtensions(), []byte{0x40, 0x40}, repeatByte(0x33, 64))
	if got := handDerivedLeafNodeTail(); !bytes.Equal(got, want) {
		t.Errorf("the hand derived tail is\n %x\nand its extensions followed by its signature are\n %x", got, want)
	}
}

// TestLeafNodeSignatureContentMatchesTheHandDerivedTbs is the field order and prefix width pin
// for the preimage, and it is the one test here that a symmetric edit cannot survive.
//
// Everything else in this file signs with this package and verifies with this package, so a
// preimage this implementation builds wrongly in a way it also reads wrongly agrees with itself
// on every input. What separates those is a statement of the structure written without
// reference to the code, which is what handDerivedLeafNodeTbs is.
//
// Three group ids and four indices, because the two fields fail in different ways. The 64 octet
// group id is the first length whose vector prefix is two octets rather than one, so a fixed one
// octet prefix moves the total by one and a WriteOpaqueLP moves it by two; the empty group id is
// the case a raw concatenation is indistinguishable from; and the indices reach past a uint8 and
// past a uint16, so an index written narrow collides with a smaller one instead of being caught.
func TestLeafNodeSignatureContentMatchesTheHandDerivedTbs(t *testing.T) {
	groupIds := [][]byte{{}, []byte("group"), repeatByte(0x5a, 64)}
	indices := []LeafIndex{0, 3, 300, 70000}
	compared := 0
	for _, source := range leafNodeSources(t) {
		for _, groupId := range groupIds {
			for _, index := range indices {
				content, err := testLeafNodeOfSource(source).signatureContent(groupId, index)
				if err != nil {
					t.Fatalf("source %d: signatureContent: %v", source, err)
				}
				want := handDerivedLeafNodeTbs(source, groupId, index)
				if !bytes.Equal(content, want) {
					t.Errorf("source %d, group id %x, index %d: the preimage is\n %x\nand the hand derivation is\n %x",
						source, groupId, index, content, want)
				}
				compared += 1
			}
		}
	}
	if compared != len(groupIds)*len(indices)*3 {
		t.Fatalf("%d preimages compared, want %d", compared, len(groupIds)*len(indices)*3)
	}
	// and the preimage is NOT the wire form: the signature is the one field of the leaf that
	// the structure it signs does not carry, and an implementation that signed over the
	// encoded LeafNode would sign over its own previous signature
	encoded, err := syntax.Marshal(testLeafNodeOfSource(LeafNodeSourceCommit))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	content, err := testLeafNodeOfSource(LeafNodeSourceCommit).signatureContent([]byte("group"), 3)
	if err != nil {
		t.Fatalf("signatureContent: %v", err)
	}
	if bytes.Contains(content, repeatByte(0x33, 64)) {
		t.Errorf("the preimage carries the leaf's own signature, so what is signed is the encoded leaf rather than its LeafNodeTBS")
	}
	if bytes.Equal(content, encoded) {
		t.Errorf("the preimage and the wire form are the same bytes")
	}
}

// ---------------------------------------------------------------------------
// signing, verifying, and what the context is bound to
// ---------------------------------------------------------------------------

// TestALeafNodeSignatureVerifiesUnderEverySource is the positive control the negative sweeps
// below rest on. A verifier that refused everything satisfies every "must not verify" property
// in this file, and only this separates it from one that works.
func TestALeafNodeSignatureVerifiesUnderEverySource(t *testing.T) {
	crypto, priv, pub := leafNodeTestSigner(t)
	for _, source := range leafNodeSources(t) {
		leaf := leafNodeSignedUnder(t, crypto, priv, pub, source, []byte("group"), 3)
		if len(leaf.Signature) == 0 {
			t.Errorf("source %d: Sign left no signature behind", source)
			continue
		}
		if err := leaf.VerifySignature(crypto, []byte("group"), 3); err != nil {
			t.Errorf("source %d: VerifySignature after Sign: %v", source, err)
		}
		// and signing twice over one leaf answers the same bytes, which is the property that
		// says the signature field is not part of what is signed
		first := bytes.Clone(leaf.Signature)
		if err := leaf.Sign(crypto, priv, []byte("group"), 3); err != nil {
			t.Fatalf("source %d: Sign a second time: %v", source, err)
		}
		if !bytes.Equal(first, leaf.Signature) {
			t.Errorf("source %d: signing one leaf twice answered %x and then %x, so the signature is an input to itself",
				source, first, leaf.Signature)
		}
	}
}

// TestALeafNodeSignatureIsBoundToItsGroupAndPositionExactlyWhereTheSourceSaysSo is the member
// substitution property, over every source rather than over the one the plan names.
//
// The defect it exists for signs and verifies perfectly against this package: a LeafNodeTBS
// built without the group id lets a leaf lifted out of one group verify in another, and one
// built without the leaf index lets a leaf verify at whatever position of the tree it is moved
// to. Both are a member substitution and neither changes a byte of the wire form.
//
// The other direction is asserted too, and it is not decoration: a key_package leaf that
// REFUSED to verify outside the context it was signed in would be a leaf no joiner could
// validate, since a KeyPackage is minted before there is a group or a position at all.
//
// The indices are swept pairwise rather than at index+1, because an index written narrower than
// a uint32 collides with a smaller one rather than being ignored: 300 against 44 and 70000
// against 4464 are the pairs a uint8 and a uint16 write identically.
func TestALeafNodeSignatureIsBoundToItsGroupAndPositionExactlyWhereTheSourceSaysSo(t *testing.T) {
	crypto, priv, pub := leafNodeTestSigner(t)
	groupIds := [][]byte{{}, []byte("group"), []byte("groups"), []byte("other"), repeatByte(0x5a, 64)}
	indices := []LeafIndex{0, 3, 44, 300, 4464, 70000}
	bound, unbound := 0, 0
	for _, source := range leafNodeSources(t) {
		isBound := leafNodeContextBoundSources[source]
		for _, signedGroup := range groupIds {
			for _, signedIndex := range indices {
				leaf := leafNodeSignedUnder(t, crypto, priv, pub, source, signedGroup, signedIndex)
				for _, group := range groupIds {
					for _, index := range indices {
						same := bytes.Equal(group, signedGroup) && index == signedIndex
						err := leaf.VerifySignature(crypto, group, index)
						switch {
						case same || !isBound:
							if err != nil {
								t.Errorf("source %d: signed at group %x index %d, verifying at group %x index %d: %v",
									source, signedGroup, signedIndex, group, index, err)
							}
						case !errors.Is(err, errBadSignature):
							t.Errorf("source %d: signed at group %x index %d and verified at group %x index %d, err = %v, want errBadSignature",
								source, signedGroup, signedIndex, group, index, err)
						}
						if isBound {
							bound += 1
							continue
						}
						unbound += 1
					}
				}
			}
		}
	}
	if bound == 0 || unbound == 0 {
		t.Fatalf("the sweep made %d bound comparisons and %d unbound ones, so one of the two arms was never reached", bound, unbound)
	}
	t.Logf("%d context comparisons over bound sources, %d over unbound ones", bound, unbound)
}

// TestEveryLeafNodeFieldTheTbsCarriesBreaksItsSignature is the field coverage the plan's five
// entry mutation list cannot state.
//
// The class is derived off the struct and the source class off the package's constants, and the
// same variant table the encoding sweep is checked against decides which fields each source
// carries -- so a field added to LeafNode, or a source added to the enum, is swept on the commit
// that lands it rather than when somebody remembers to extend a list.
//
// Both directions, which is what makes it a statement about the PREIMAGE rather than about the
// signature: a field the source carries must break the signature when it changes, and a field
// the source does not carry must not. The second is what catches a preimage that wrote a variant
// under the wrong source -- a parent hash folded into an update leaf's TBS is a leaf whose
// signature depends on a field the wire form does not carry, so it verifies for the sender and
// for nobody who decoded it.
//
// Signature is in the carried class under every source, and it breaks verification as the
// signature rather than as content. What says it is not IN the preimage is
// TestLeafNodeSignatureContentMatchesTheHandDerivedTbs, which reads the bytes.
func TestEveryLeafNodeFieldTheTbsCarriesBreaksItsSignature(t *testing.T) {
	crypto, priv, pub := leafNodeTestSigner(t)
	sources := leafNodeSources(t)
	paths := leafNodeCodecFieldPaths(t)
	if !slices.Contains(paths, "Signature") {
		t.Fatalf("the field walk read %v and LeafNode certainly has a Signature, so the class below is read off something else", paths)
	}
	variant := map[string]LeafNodeSource{}
	for _, source := range sources {
		for _, path := range leafNodeVariantPaths[source] {
			variant[path] = source
		}
	}
	covered := map[string]bool{}
	for _, source := range sources {
		base := leafNodeSignedUnder(t, crypto, priv, pub, source, []byte("group"), 3)
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
			verifiable := 0
			for _, edit := range edits {
				mutated := base.Clone()
				edit.apply(leafNodeFieldAt(mutated, path))
				err := mutated.VerifySignature(crypto, []byte("group"), 3)
				if err != nil && !errors.Is(err, errBadSignature) {
					// a structural refusal rather than a signature that stopped verifying:
					// the credential type outside the profile is the one edit here that
					// produces one, and a preimage that cannot be built is not a preimage
					// that ignored the field
					continue
				}
				verifiable += 1
				if err != nil {
					observed = true
					covered[path] = true
				}
			}
			if verifiable == 0 {
				t.Errorf("source %d: every edit to %s was refused before a signature was checked, so this field was never observed", source, path)
				continue
			}
			if carried && !observed {
				t.Errorf("source %d: %d edits to %s all left the signature verifying, so the leaf is authenticated without that field",
					source, verifiable, path)
			}
			if !carried && observed {
				t.Errorf("source %d: an edit to %s broke the signature, and source %d does not carry that field, so its preimage covers something its encoding does not",
					source, path, source)
			}
		}
	}
	for _, path := range paths {
		if !covered[path] {
			t.Errorf("%s broke no signature under any of the %d sources, so nothing this package signs depends on it",
				path, len(sources))
		}
	}
	t.Logf("%d field paths swept against the signature over %d sources", len(paths), len(sources))
}

// TestALeafNodeSignatureIsRefusedAtEveryFlippedBit sweeps the signature over its own length
// rather than sampling it.
//
// A comparison that stopped at the first byte, at 32 bytes, or anywhere short of the whole
// accepts a forgery whose prefix matches, and a sampled sweep tests the offsets somebody chose.
// The length is read off the signature, so a scheme with a different signature size is swept
// whole on the commit that lands it.
func TestALeafNodeSignatureIsRefusedAtEveryFlippedBit(t *testing.T) {
	crypto, priv, pub := leafNodeTestSigner(t)
	leaf := leafNodeSignedUnder(t, crypto, priv, pub, LeafNodeSourceCommit, []byte("group"), 3)
	if len(leaf.Signature) == 0 {
		t.Fatal("the signed leaf carries no signature, so this sweep runs over nothing")
	}
	refused := 0
	for at := range leaf.Signature {
		for bit := 0; bit < 8; bit += 1 {
			flipped := leaf.Clone()
			flipped.Signature[at] ^= 1 << bit
			if err := flipped.VerifySignature(crypto, []byte("group"), 3); !errors.Is(err, errBadSignature) {
				t.Errorf("byte %d bit %d flipped: err = %v, want errBadSignature", at, bit, err)
				continue
			}
			refused += 1
		}
	}
	if want := 8 * len(leaf.Signature); refused != want {
		t.Fatalf("%d of the %d single bit forgeries were refused", refused, want)
	}
	t.Logf("%d single bit forgeries refused over a %d byte signature", refused, len(leaf.Signature))
}

// TestALeafNodeSignatureOfTheWrongLengthIsRefusedAndNeverPanics is the other half of the
// comparison contract: a length mismatch is a refusal, never a panic and never a comparison over
// whichever of the two is shorter.
//
// nil and empty are swept separately even though they encode alike, because they are different
// values in Go and the read path produces both -- a leaf built by hand carries nil and a decoded
// one carries an allocated slice. Every truncation and every over long length is swept rather
// than a chosen few, derived off the real signature's own length.
func TestALeafNodeSignatureOfTheWrongLengthIsRefusedAndNeverPanics(t *testing.T) {
	crypto, priv, pub := leafNodeTestSigner(t)
	leaf := leafNodeSignedUnder(t, crypto, priv, pub, LeafNodeSourceCommit, []byte("group"), 3)
	full := len(leaf.Signature)
	if full == 0 {
		t.Fatal("the signed leaf carries no signature, so this sweep runs over nothing")
	}
	cases := map[string][]byte{"nil": nil}
	for n := 0; n <= 2*full; n += 1 {
		if n == full {
			continue
		}
		short := bytes.Clone(leaf.Signature)
		for len(short) < n {
			short = append(short, byte(len(short)))
		}
		cases[fmt.Sprintf("%d bytes", n)] = short[:n]
	}
	refused := 0
	for name, signature := range cases {
		wrong := leaf.Clone()
		wrong.Signature = signature
		err := func() (err error) {
			defer func() {
				if raised := recover(); raised != nil {
					t.Errorf("a %s signature panicked with %v rather than being refused", name, raised)
					err = errBadSignature
				}
			}()
			return wrong.VerifySignature(crypto, []byte("group"), 3)
		}()
		if !errors.Is(err, errBadSignature) {
			t.Errorf("a %s signature: err = %v, want errBadSignature", name, err)
			continue
		}
		refused += 1
	}
	if refused != len(cases) {
		t.Fatalf("%d of the %d wrong length signatures were refused", refused, len(cases))
	}
	t.Logf("%d wrong length signatures refused, against a real one of %d bytes", refused, full)
}

// TestALeafNodeSignatureUnderAnotherKeyIsRefused covers the third way a leaf can be
// unauthentic: the content and the context are right and the key is not.
//
// Both directions are swept. A leaf signed by one key and carrying another's signature_key is
// the substitution an attacker makes; a leaf carrying a signature_key of the wrong LENGTH is the
// one that reaches ed25519.Verify, which panics on any length but 32, so a refusal here is also
// the statement that the length gate in front of it is doing its job.
func TestALeafNodeSignatureUnderAnotherKeyIsRefused(t *testing.T) {
	crypto, priv, pub := leafNodeTestSigner(t)
	otherPriv, otherPub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	if bytes.Equal(pub, otherPub) {
		t.Fatal("two key pairs came back with one public key, so this test compares a key against itself")
	}
	for _, source := range leafNodeSources(t) {
		// signed by the right key, verified against somebody else's public key
		leaf := leafNodeSignedUnder(t, crypto, priv, pub, source, []byte("group"), 3)
		leaf.SignatureKey = otherPub
		if err := leaf.VerifySignature(crypto, []byte("group"), 3); !errors.Is(err, errBadSignature) {
			t.Errorf("source %d: verified under another public key, err = %v, want errBadSignature", source, err)
		}
		// signed by somebody else, carrying the public key it claims to be
		signedByAnother := leafNodeSignedUnder(t, crypto, otherPriv, pub, source, []byte("group"), 3)
		if err := signedByAnother.VerifySignature(crypto, []byte("group"), 3); !errors.Is(err, errBadSignature) {
			t.Errorf("source %d: signed by another private key, err = %v, want errBadSignature", source, err)
		}
		// and a signature key of a length ed25519 cannot verify against
		for _, length := range []int{0, 1, 31, 33, 64} {
			short := leafNodeSignedUnder(t, crypto, priv, pub, source, []byte("group"), 3)
			short.SignatureKey = SignaturePublicKey(repeatByte(0x7e, length))
			err := func() (err error) {
				defer func() {
					if raised := recover(); raised != nil {
						t.Errorf("source %d: a %d byte signature key panicked with %v rather than being refused",
							source, length, raised)
						err = errBadSignature
					}
				}()
				return short.VerifySignature(crypto, []byte("group"), 3)
			}()
			if !errors.Is(err, errBadSignature) {
				t.Errorf("source %d: a %d byte signature key, err = %v, want errBadSignature", source, length, err)
			}
		}
	}
}

// TestVerifySignatureRefusesAnUnknownSourceAsItself is the one refusal that is NOT a signature
// failure, and it is separated on purpose: a leaf whose leaf_node_source is not one this package
// reads has no preimage at all, so reporting it as a bad signature would send a caller looking
// for a forgery over a structure nobody could have signed.
func TestVerifySignatureRefusesAnUnknownSourceAsItself(t *testing.T) {
	crypto, priv, pub := leafNodeTestSigner(t)
	known := leafNodeSources(t)
	unknown := []LeafNodeSource{}
	for candidate := 0; candidate < 256 && len(unknown) < 4; candidate += 1 {
		if !slices.Contains(known, LeafNodeSource(candidate)) {
			unknown = append(unknown, LeafNodeSource(candidate))
		}
	}
	if len(unknown) == 0 {
		t.Fatal("every one of the 256 source octets is a declared source, so this test has nothing to refuse")
	}
	for _, source := range unknown {
		leaf := leafNodeSignedUnder(t, crypto, priv, pub, LeafNodeSourceCommit, []byte("group"), 3)
		leaf.LeafNodeSource = source
		if err := leaf.VerifySignature(crypto, []byte("group"), 3); !errors.Is(err, ErrTreeMalformed) {
			t.Errorf("source %d: err = %v, want ErrTreeMalformed", source, err)
		}
		if err := leaf.Sign(crypto, priv, []byte("group"), 3); !errors.Is(err, ErrTreeMalformed) {
			t.Errorf("source %d: Sign err = %v, want ErrTreeMalformed", source, err)
		}
	}
}

// ---------------------------------------------------------------------------
// the published corpus
// ---------------------------------------------------------------------------

// leafNodeTreeValidationVector reads the two columns this file needs out of the mlswg
// tree-validation family: the ratchet tree and the group id its leaves are bound to.
//
// tree_math_test.go reads the same file for its resolutions column and declares its own view of
// it. Two views of one corpus rather than one shared struct, because the two tests want
// different columns and a struct that carried both would make a change to either one a change to
// both.
type leafNodeTreeValidationVector struct {
	CipherSuite uint16 `json:"cipher_suite"`
	Tree        string `json:"tree"`
	GroupId     string `json:"group_id"`
}

// publishedLeafNodes answers every leaf of one published ratchet tree, keyed by the leaf index
// it sits at, decoded through this package's own LeafNode codec.
//
// The WALK is tree_math_test.go's presentation reader rather than a codec of this package,
// which is what keeps the oracle independent of the thing it judges: only the leaf's own bytes
// are handed to this package, and where each leaf starts and ends is decided by a reader that
// skips every field by its length prefix.
func publishedLeafNodes(t *testing.T, label string, tree []byte) map[LeafIndex]*LeafNode {
	t.Helper()
	reader := &presentationReader{body: tree}
	total := reader.readLength()
	if reader.failed || reader.offset+total != len(tree) {
		t.Fatalf("%s: the ratchet tree is not one presentation-language vector", label)
	}
	end := reader.offset + total
	leaves := map[LeafIndex]*LeafNode{}
	node := 0
	for reader.offset < end && !reader.failed {
		if reader.readUint8() != 0 {
			switch reader.readUint8() {
			case 1:
				at := reader.offset
				reader.skipLeafNode()
				if reader.failed {
					break
				}
				if node%2 != 0 {
					t.Fatalf("%s: node %d is a leaf at an odd node index", label, node)
				}
				leaf := &LeafNode{}
				if err := syntax.Unmarshal(tree[at:reader.offset], leaf); err != nil {
					t.Fatalf("%s: node %d: decode the published leaf: %v", label, node, err)
				}
				leaves[LeafIndex(node/2)] = leaf
			case 2:
				reader.readParentNodeUnmerged()
			default:
				t.Fatalf("%s: node %d is neither a leaf nor a parent", label, node)
			}
		}
		node += 1
	}
	if reader.failed || reader.offset != end {
		t.Fatalf("%s: the ratchet tree did not decode to a whole number of nodes", label)
	}
	return leaves
}

// The counts the sweep below confirms, so a walk that quietly found nothing fails here rather
// than reporting a clean run over an empty corpus. They are measured off the vendored file and
// are its property rather than this implementation's: a decoder that stopped early, a suite
// filter that matched nothing and a verifier that refused everything all move one of them.
const (
	leafNodeKatSignatureCount  = 322
	leafNodeKatKeyPackageLeafs = 34
	leafNodeKatBoundLeafs      = 288
)

// TestPublishedLeafNodeSignaturesVerifyAgainstTheirGroupAndPosition is the known answer test,
// and it is the only assertion in this file whose signatures this package did not compute.
//
// Everything else here signs with this implementation and verifies with it, so a LeafNodeTBS
// this package builds wrongly and reads wrongly is invisible to all of it. These signatures were
// made by the working group's own implementations over their own reading of section 7.2, so a
// preimage that omitted the group id, omitted the leaf index, ordered a field differently or
// wrote a prefix at the wrong width fails here and nowhere else in this package.
//
// The published trees carry both arms of the select -- leaves whose source is key_package and
// leaves whose source is commit -- and the counts below require both, because a corpus of one
// arm would say nothing about the conditional at all.
//
// The negative control runs beside it. Every case of a vendored corpus agrees with this
// implementation, so a verifier that answered nil for everything passes the whole run; what
// separates it is asking the same leaves the wrong question. A context bound leaf must refuse
// its own signature at another group and at another position, and an unbound one must accept
// both, which is the conditional stated over bytes this package did not produce.
func TestPublishedLeafNodeSignaturesVerifyAgainstTheirGroupAndPosition(t *testing.T) {
	entries := LoadVectorFile(t, treeValidationVectorFile)
	if len(entries) != treeValidationEntryCount {
		t.Fatalf("tree-validation entries: %d, want %d", len(entries), treeValidationEntryCount)
	}
	verified := 0
	declined := 0
	bySource := map[LeafNodeSource]int{}
	substitutionsRefused := 0
	for entry, raw := range entries {
		vector := leafNodeTreeValidationVector{}
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatalf("entry %d: %v", entry, err)
		}
		suite, implemented := implementedSuite(vector.CipherSuite)
		if !implemented {
			declined += 1
			continue
		}
		label := fmt.Sprintf("tree-validation entry %d", entry)
		crypto := mustProvider(t, suite)
		tree := mustDecodeHex(t, label+" ratchet tree", vector.Tree)
		groupId := mustDecodeHex(t, label+" group id", vector.GroupId)
		if len(groupId) == 0 {
			t.Fatalf("%s publishes no group id, so the binding this reads has nothing to be bound to", label)
		}
		leaves := publishedLeafNodes(t, label, tree)
		if len(leaves) == 0 {
			t.Fatalf("%s: the walk found no leaf in a published ratchet tree", label)
		}
		for index, leaf := range leaves {
			if err := leaf.VerifySignature(crypto, groupId, index); err != nil {
				t.Errorf("%s: the published leaf at index %d does not verify: %v", label, index, err)
				continue
			}
			bySource[leaf.LeafNodeSource] += 1
			verified += 1
			// the same leaf, asked the wrong question
			otherGroup := bytes.Clone(groupId)
			otherGroup[0] ^= 0xff
			atOtherGroup := leaf.VerifySignature(crypto, otherGroup, index)
			atOtherIndex := leaf.VerifySignature(crypto, groupId, index+1)
			if !leafNodeContextBoundSources[leaf.LeafNodeSource] {
				if atOtherGroup != nil || atOtherIndex != nil {
					t.Errorf("%s: the published leaf at index %d has source %d, which binds no context, and refused another group (%v) or another position (%v)",
						label, index, leaf.LeafNodeSource, atOtherGroup, atOtherIndex)
				}
				continue
			}
			if !errors.Is(atOtherGroup, errBadSignature) {
				t.Errorf("%s: the published leaf at index %d verified in another group, err = %v",
					label, index, atOtherGroup)
				continue
			}
			if !errors.Is(atOtherIndex, errBadSignature) {
				t.Errorf("%s: the published leaf at index %d verified at index %d, err = %v",
					label, index, index+1, atOtherIndex)
				continue
			}
			substitutionsRefused += 1
		}
	}
	if declined == len(entries) {
		t.Fatal("every published entry was declined by the suite filter, so this ran over nothing")
	}
	if verified != leafNodeKatSignatureCount {
		t.Errorf("%d published leaf signatures verified, want %d", verified, leafNodeKatSignatureCount)
	}
	if bySource[LeafNodeSourceKeyPackage] != leafNodeKatKeyPackageLeafs {
		t.Errorf("%d published leaves carry the key_package source, want %d",
			bySource[LeafNodeSourceKeyPackage], leafNodeKatKeyPackageLeafs)
	}
	bound := 0
	for source, count := range bySource {
		if leafNodeContextBoundSources[source] {
			bound += count
		}
	}
	if bound != leafNodeKatBoundLeafs {
		t.Errorf("%d published leaves carry a context bound source, want %d", bound, leafNodeKatBoundLeafs)
	}
	if substitutionsRefused != bound {
		t.Errorf("%d of the %d context bound leaves refused a substitution", substitutionsRefused, bound)
	}
	t.Logf("%d published leaf signatures verified over %d entries (%d declined), by source %v",
		verified, len(entries)-declined, declined, bySource)
}

// ---------------------------------------------------------------------------
// NewLeafNode
// ---------------------------------------------------------------------------

// leafNodeTestCapabilities is a capabilities set carrying the extension the leaf below uses, so
// nothing here is refused for a reason that is not this task's.
func leafNodeTestCapabilities() Capabilities {
	return Capabilities{
		Versions:     []ProtocolVersion{ProtocolVersionMls10},
		CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20Sha256Ed25519},
		Extensions:   []ExtensionType{ExtensionTypeUrmessageLeafKeys},
		Credentials:  []CredentialType{CredentialTypeBasic},
	}
}

// TestNewLeafNodeSignsAKeyPackageSourceLeaf is the constructor's own contract: the source, the
// signature key, the lifetime window and a signature that verifies in any context.
func TestNewLeafNodeSignsAKeyPackageSourceLeaf(t *testing.T) {
	crypto, priv, pub := leafNodeTestSigner(t)
	_, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	exts := []Extension{{ExtensionType: ExtensionTypeUrmessageLeafKeys, ExtensionData: []byte("k")}}
	leaf, err := NewLeafNode(crypto, priv, BasicCredential([]byte("alice")), encPub,
		leafNodeTestCapabilities(), exts)
	if err != nil {
		t.Fatalf("NewLeafNode: %v", err)
	}
	if leaf.LeafNodeSource != LeafNodeSourceKeyPackage {
		t.Errorf("source = %d, want key_package", leaf.LeafNodeSource)
	}
	// the public key it installed is the one belonging to the private key it was handed, and
	// not a fresh pair of its own: a leaf signed by a key nobody holds verifies against itself
	// and is refused by every later Update the member sends
	if !bytes.Equal(leaf.SignatureKey, pub) {
		t.Errorf("signature key = %x, want the public half %x of the signer it was handed", leaf.SignatureKey, pub)
	}
	now := uint64(time.Now().Unix())
	if leaf.Lifetime.NotBefore > now || leaf.Lifetime.NotAfter <= now {
		t.Errorf("lifetime = %+v, and the current second is %d, which it must contain", leaf.Lifetime, now)
	}
	if leaf.Lifetime.NotAfter <= leaf.Lifetime.NotBefore {
		t.Errorf("lifetime = %+v, want a non empty window", leaf.Lifetime)
	}
	// a key_package leaf is bound to no group and no position, so any context verifies
	for _, group := range [][]byte{nil, {}, []byte("any group"), repeatByte(0x5a, 64)} {
		for _, index := range []LeafIndex{0, 9, 70000} {
			if err := leaf.VerifySignature(crypto, group, index); err != nil {
				t.Errorf("VerifySignature at group %x index %d: %v", group, index, err)
			}
		}
	}
}

// TestNewLeafNodeRefusesASignerItCannotDeriveAPublicKeyFrom is the refusal that would otherwise
// be a panic. ed25519.NewKeyFromSeed panics on any length but 32, so a constructor handed a
// truncated or an already expanded private key would take the process down rather than answering
// an error -- and an expanded key is exactly what a caller reaching for go's own key type holds.
func TestNewLeafNodeRefusesASignerItCannotDeriveAPublicKeyFrom(t *testing.T) {
	crypto, priv, _ := leafNodeTestSigner(t)
	_, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	for _, length := range []int{0, 1, 31, 33, 64} {
		leaf, err := func() (leaf *LeafNode, err error) {
			defer func() {
				if raised := recover(); raised != nil {
					t.Errorf("a %d byte signer panicked with %v rather than being refused", length, raised)
					err = ErrBadSignatureKey
				}
			}()
			return NewLeafNode(crypto, SignaturePrivateKey(repeatByte(0x7e, length)),
				BasicCredential([]byte("alice")), encPub, leafNodeTestCapabilities(), nil)
		}()
		if !errors.Is(err, ErrBadSignatureKey) {
			t.Errorf("a %d byte signer: err = %v, want ErrBadSignatureKey", length, err)
		}
		if leaf != nil {
			t.Errorf("a %d byte signer answered a leaf alongside %v", length, err)
		}
	}
	// and the control: the right length is not refused, or the rows above are satisfied by a
	// constructor that refuses everything
	if _, err := NewLeafNode(crypto, priv, BasicCredential([]byte("alice")), encPub,
		leafNodeTestCapabilities(), nil); err != nil {
		t.Errorf("NewLeafNode refused a signer of the right length: %v", err)
	}
}

// TestNewLeafNodeKeepsNothingTheCallerCanStillWriteInto is the retention property, stated over
// the leaf rather than over one field.
//
// The leaf outlives the call and every one of its vectors came from the caller, who usually
// holds a longer buffer it goes on writing into. A retained slice is a leaf that changes after
// it was signed: the signature verified when it was made and does not afterwards, and there is
// nothing in between to point at. Every vector reachable from the value is written through
// after the call, which is the walk TestTheCloneWalkReachesEverySliceOfTheStructure already
// derives off the type.
func TestNewLeafNodeKeepsNothingTheCallerCanStillWriteInto(t *testing.T) {
	crypto, priv, _ := leafNodeTestSigner(t)
	_, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	identity := []byte("alice")
	encKey := HpkePublicKey(bytes.Clone(encPub))
	caps := leafNodeTestCapabilities()
	exts := []Extension{{ExtensionType: ExtensionTypeUrmessageLeafKeys, ExtensionData: []byte("k")}}
	leaf, err := NewLeafNode(crypto, priv, Credential{CredentialType: CredentialTypeBasic, Identity: identity},
		encKey, caps, exts)
	if err != nil {
		t.Fatalf("NewLeafNode: %v", err)
	}
	before, err := syntax.Marshal(leaf)
	if err != nil {
		t.Fatalf("Marshal the leaf before the caller writes: %v", err)
	}
	// the caller writes through every array it still holds
	for i := range identity {
		identity[i] ^= 0xff
	}
	for i := range encKey {
		encKey[i] ^= 0xff
	}
	for i := range caps.Versions {
		caps.Versions[i] += 1
	}
	for i := range caps.CipherSuites {
		caps.CipherSuites[i] += 1
	}
	for i := range caps.Extensions {
		caps.Extensions[i] += 1
	}
	for i := range caps.Credentials {
		caps.Credentials[i] += 1
	}
	for i := range exts {
		exts[i].ExtensionType += 1
		for j := range exts[i].ExtensionData {
			exts[i].ExtensionData[j] ^= 0xff
		}
	}
	after, err := syntax.Marshal(leaf)
	if err != nil {
		t.Fatalf("Marshal the leaf after the caller writes: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("the leaf encoded to\n %x\nbefore the caller wrote through its own arrays and to\n %x\nafterwards",
			before, after)
	}
	if err := leaf.VerifySignature(crypto, nil, 0); err != nil {
		t.Errorf("the leaf stopped verifying after the caller wrote through its own arrays: %v", err)
	}
}

// ---------------------------------------------------------------------------
// what the package wide provider gates need in order to call NewLeafNode
// ---------------------------------------------------------------------------

// The three structured arguments NewLeafNode takes, each built fresh on every call.
//
// Fresh storage is the load bearing part rather than tidiness: the perturbation rule below
// edits a value IN PLACE, and an edit reaching a slice element through a shallow copy writes
// into the base argument every other row of the gate is built from -- which would move the
// answer the gate is comparing against and report a defect in whichever row ran next.
//
// Every field carries something and no two carry the same octets, so an edit to any one of
// them has somewhere to move and a constructor that read one field where it meant another is
// not answered by its neighbour.
func leafNodeStubCredential() Credential {
	return Credential{CredentialType: CredentialTypeBasic, Identity: ascendingBytes(0x12, 9)}
}

func leafNodeStubCapabilities() Capabilities {
	return Capabilities{
		Versions:     []ProtocolVersion{ProtocolVersionMls10},
		CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20Sha256Ed25519},
		Extensions:   []ExtensionType{ExtensionTypeUrmessageLeafKeys},
		Proposals:    []ProposalType{},
		Credentials:  []CredentialType{CredentialTypeBasic},
	}
}

func leafNodeStubExtensions() []Extension {
	return []Extension{{ExtensionType: ExtensionTypeUrmessageLeafKeys, ExtensionData: ascendingBytes(0x13, 6)}}
}

// leafNodeStubArgumentSources is the type of each of the three, with the constructor that
// answers it, so the dispatch and the base arguments cannot name different values.
func leafNodeStubArgumentSources() map[reflect.Type]func() any {
	return map[reflect.Type]func() any{
		reflect.TypeOf(Credential{}):     func() any { return leafNodeStubCredential() },
		reflect.TypeOf(Capabilities{}):   func() any { return leafNodeStubCapabilities() },
		reflect.TypeOf([]Extension(nil)): func() any { return leafNodeStubExtensions() },
	}
}

// providerLeafNodeArgumentPerturbations is the stub gate's rule for those three.
//
// The gate's own rules reach a run of bytes, a string, an integer, a *GroupContext and a
// provider, and a leaf's credential, capabilities and extensions are none of those: a rule
// that is missing is fatal there rather than silent, which is what brought this here.
//
// The moves are DERIVED off the value with leafNodeEditsOf, the same derivation the codec
// sweeps in this file run on, rather than written per field. A written list understates the
// class the moment a field is added to any of the three structures, and a gate reading a stale
// list reports exactly what a complete one reports. Every edit it derives changes the encoding
// of the leaf, and therefore the signature NewLeafNode answers -- including the one that
// changes the credential type, which NewLeafNode refuses outright, and a refusal is as much an
// observation of the argument as a different signature is.
//
// Each perturbed value is built from a FRESH base rather than copied from the one it was
// handed, because the edits write in place and a shallow copy shares every slice.
func providerLeafNodeArgumentPerturbations(t *testing.T, operation string, parameter providerParameter,
	argument reflect.Value) ([]providerPerturbation, bool) {
	t.Helper()
	fresh, handled := leafNodeStubArgumentSources()[argument.Type()]
	if !handled {
		return nil, false
	}
	// the base the gate handed in has to be what the constructor answers, or every move below
	// is a move away from a value nothing was ever called with
	if !reflect.DeepEqual(argument.Interface(), fresh()) {
		t.Fatalf("the base argument for %s.%s is %v and the constructor for that type answers %v, so the perturbations move away from a value the gate did not call with",
			operation, parameter.name, argument.Interface(), fresh())
	}
	moved := []providerPerturbation{}
	for _, edit := range leafNodeEditsOf(parameter.name, argument, leafNodeSources(t)) {
		box := reflect.New(argument.Type()).Elem()
		box.Set(reflect.ValueOf(fresh()))
		edit.apply(box)
		if reflect.DeepEqual(box.Interface(), argument.Interface()) {
			t.Fatalf("the edit %q left %s.%s equal to the base argument, so the gate would call it twice with the same value",
				edit.name, operation, parameter.name)
		}
		moved = append(moved, providerPerturbation{where: edit.name, value: box})
	}
	if len(moved) == 0 {
		t.Fatalf("no edit was derived for %s.%s, declared %s, so nothing moves it",
			operation, parameter.name, parameter.typeName)
	}
	return moved, true
}

// TestTheLeafNodeStubArgumentsAreFreshStorageEveryCall is the control on the sentence above.
// A constructor answering a package level value would hand every perturbation the same slices,
// the in place edits would accumulate, and the gate reading them would compare a base argument
// that had already been written through.
func TestTheLeafNodeStubArgumentsAreFreshStorageEveryCall(t *testing.T) {
	for at, fresh := range leafNodeStubArgumentSources() {
		first := reflect.ValueOf(fresh())
		second := reflect.ValueOf(fresh())
		if !reflect.DeepEqual(first.Interface(), second.Interface()) {
			t.Errorf("the constructor for %s answered %v and then %v", at, first.Interface(), second.Interface())
			continue
		}
		edits := leafNodeEditsOf("value", first, leafNodeSources(t))
		if len(edits) == 0 {
			t.Errorf("no edit was derived for %s, so this control observed nothing", at)
			continue
		}
		box := reflect.New(at).Elem()
		box.Set(first)
		edits[0].apply(box)
		if reflect.DeepEqual(second.Interface(), fresh()) {
			continue
		}
		t.Errorf("editing one %s answered by the constructor changed what the constructor answers next, so the two share storage", at)
	}
}

// ---------------------------------------------------------------------------
// what the package wide stub gate cannot hold NewLeafNode to
// ---------------------------------------------------------------------------

// leafNodeWithoutItsClock is one leaf encoded with its Lifetime replaced by a fixed window.
//
// The lifetime is the one field of a key_package leaf that is not a function of what
// NewLeafNode was handed -- it is a wall clock stamp -- so two leaves built a second apart
// differ in it and, because the lifetime is inside the LeafNodeTBS, in their signatures too.
// Normalising it is what makes two calls comparable at all, and it is exactly why the package
// wide stub gate excuses this constructor from every comparison it makes across calls.
//
// The whole leaf is encoded rather than a chosen field, so an argument that reached any part of
// the structure is observed. The SIGNATURE is dropped with the lifetime, because it covers the
// lifetime and would carry the clock straight back in; what holds the signature to depending on
// each of these fields is TestEveryLeafNodeFieldTheTbsCarriesBreaksItsSignature, over the same
// derived field class.
func leafNodeWithoutItsClock(t *testing.T, leaf *LeafNode) string {
	t.Helper()
	normalised := leaf.Clone()
	normalised.Lifetime = Lifetime{NotBefore: 1, NotAfter: 2}
	normalised.Signature = nil
	encoded, err := syntax.Marshal(normalised)
	if err != nil {
		t.Fatalf("encode a leaf with its clock normalised out: %v", err)
	}
	return hex.EncodeToString(encoded)
}

// TestNewLeafNodeReadsEveryArgumentItWasHanded is the half of the package wide stub gate that
// the wall clock exemption takes away, put back over the arguments this constructor has.
//
// The property is the gate's: an argument that changes must change the answer, or the
// constructor is a function of fewer things than its signature says. Two differences. The
// answer is read with the lifetime normalised out, which is what makes the comparison stable
// across a second boundary; and the moves are DERIVED off each argument with the same
// leafNodeEditsOf the codec sweeps in this file use, so an argument that grows a field is swept
// on the commit that lands it rather than when somebody remembers to extend a list.
//
// A refusal counts as an observation, for the reason the stub gate gives: an argument that
// moved a call from accepted to rejected has been read just as surely as one that moved the
// bytes.
func TestNewLeafNodeReadsEveryArgumentItWasHanded(t *testing.T) {
	crypto, priv, _ := leafNodeTestSigner(t)
	_, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	// every argument in one place, so the sweep below is over the constructor's whole
	// parameter list rather than over the ones this test thought of
	arguments := func() []any {
		return []any{
			SignaturePrivateKey(bytes.Clone(priv)),
			leafNodeStubCredential(),
			HpkePublicKey(bytes.Clone(encPub)),
			leafNodeStubCapabilities(),
			leafNodeStubExtensions(),
		}
	}
	names := []string{"signer", "cred", "encKey", "caps", "exts"}
	build := func(with []any) string {
		leaf, buildErr := NewLeafNode(crypto, with[0].(SignaturePrivateKey), with[1].(Credential),
			with[2].(HpkePublicKey), with[3].(Capabilities), with[4].([]Extension))
		if buildErr != nil {
			return "refused: " + buildErr.Error()
		}
		return leafNodeWithoutItsClock(t, leaf)
	}
	base := build(arguments())
	if strings.HasPrefix(base, "refused") {
		t.Fatalf("NewLeafNode refused this test's own arguments (%s), so every row below compares two refusals", base)
	}
	// the control on the normalisation: two calls with one argument list answer the same
	// thing, or every "it moved" below is the clock rather than the argument
	if repeated := build(arguments()); repeated != base {
		t.Fatalf("NewLeafNode answered\n %s\nand then\n %s\nfor one argument list with the clock normalised out",
			base, repeated)
	}
	moved := 0
	for at, name := range names {
		box := reflect.New(reflect.TypeOf(arguments()[at])).Elem()
		box.Set(reflect.ValueOf(arguments()[at]))
		edits := leafNodeEditsOf(name, box, leafNodeSources(t))
		if len(edits) == 0 {
			t.Errorf("no edit was derived for %s, so nothing below observed it", name)
			continue
		}
		for _, edit := range edits {
			with := arguments()
			edited := reflect.New(reflect.TypeOf(with[at])).Elem()
			edited.Set(reflect.ValueOf(with[at]))
			edit.apply(edited)
			with[at] = edited.Interface()
			if answer := build(with); answer == base {
				t.Errorf("NewLeafNode answered the same leaf with %s, so it does not read the %s it was handed",
					edit.name, name)
				continue
			}
			moved += 1
		}
	}
	if moved == 0 {
		t.Fatal("no edit to any argument changed the leaf, so this sweep observed nothing")
	}
	t.Logf("%d derived edits across %d arguments each changed the leaf", moved, len(names))
}

// TestNewLeafNodeRoutesThroughTheProviderItWasHanded is the other half the exemption takes
// away: the provider argument itself.
//
// A constructor that reached for ed25519 directly, or built a provider of its own out of a
// hardcoded suite, answers a leaf that verifies against every leaf in this package and against
// every published ratchet tree -- both registered suites and every corpus here are Ed25519,
// which is the scheme it would have hardcoded. What separates the two is a provider that
// answers differently, and the refusal it produces here is the observation: a provider whose
// signing half flips the signature it answers cannot satisfy this constructor's own verify.
func TestNewLeafNodeRoutesThroughTheProviderItWasHanded(t *testing.T) {
	crypto, priv, _ := leafNodeTestSigner(t)
	_, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	overTheRealProvider, err := NewLeafNode(crypto, priv, leafNodeStubCredential(), encPub,
		leafNodeStubCapabilities(), leafNodeStubExtensions())
	if err != nil {
		t.Fatalf("NewLeafNode: %v", err)
	}
	tagging := &taggingCryptoProvider{inner: crypto}
	overTheTaggingProvider, err := NewLeafNode(tagging, priv, leafNodeStubCredential(), encPub,
		leafNodeStubCapabilities(), leafNodeStubExtensions())
	if err == nil {
		t.Fatalf("NewLeafNode answered a leaf whose signature is %x over a provider that flips every signature it answers, and one whose signature is %x over the real one; it called %v",
			overTheTaggingProvider.Signature, overTheRealProvider.Signature, tagging.calls)
	}
	if overTheTaggingProvider != nil {
		t.Errorf("NewLeafNode answered a leaf alongside %v", err)
	}
	if !errors.Is(err, errBadSignature) {
		t.Errorf("NewLeafNode over a provider that flips every signature answered %v, want the refusal its own verify makes", err)
	}
	// and the call really did go through the provider rather than past it
	if len(tagging.calls) == 0 {
		t.Error("NewLeafNode reached the provider it was handed not at all")
	}
}
