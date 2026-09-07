// The record key ladder's four derivations, held against vectors computed outside this tree and
// against the property that a rung does not lead backwards.
//
// It is a file of its own rather than more of keyschedule_test.go for one reason: the ladder is
// what both ratchets are built on, and the gates below are read together with ratchet_test.go's
// far more often than with the storage root's. Nothing here is scoped by file name -- every
// derived class in this package is derived over the whole directory -- so the split costs no
// coverage.
package messagegroup

import (
	"encoding/binary"
	"errors"
	"go/ast"
	"maps"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// THE DERIVATION, so a reader can re-derive every octet below without running this package.
// The class key is the DURABLE one of the vector keyschedule_test.go already pins, so this file
// starts from a value that file holds against python:
//
//	class_key = durable/v1 of the pinned storage root
//	          = bf987968f45bf2c8cb50c0639616df062dde171c9b7a2394f701a84e3ceb6838
//
//	LP(leaf)  = 00 00 00 04 | u32be(leaf)                       the four octet reading, M1-8
//
//	record_key[0]   = HKDF-Expand(class_key,      "sender/v1" | LP(leaf), 32)
//	record_key[i+1] = HKDF-Expand(record_key[i],  "ratchet/v1",           32)
//	key_head | nonce_head = HKDF-Expand(record_key[i], "rec/v1/head", 56)
//	key_body | nonce_body = HKDF-Expand(record_key[i], "rec/v1/body", 56)
//
// The hex was computed outside this tree with python's hmac and hashlib, and every value is
// checked here against keyschedule_test.go's RFC 5869 reference as well -- so a vector is wrong
// only if two implementations sharing no code are wrong in the same way.
//
// recordKeyZeroMinimalLpKatHex is the OTHER reading of LP(leaf_index): a minimal encoding, five
// octets for leaf 3 where the four octet reading gives eight. It is pinned so that this file can
// say which reading the package takes rather than only that it is self consistent, because the
// two produce values of identical width from identical inputs and no round trip inside one
// implementation can tell them apart. Open item M1-8 is the ruling.
const (
	recordKeyZeroLeaf0KatHex   = "42a2c7f0788361ce00b5e4ea2de15013898e0624cd40a3213216810548c0a00f"
	recordKeyZeroLeaf3KatHex   = "f9a9ef716a3ed6a0846a591e57d63433813a8ac06200c3ae56f35d1f430f065f"
	recordKeyZeroLeaf7KatHex   = "f5e52f25855271d558c808c766bf0e3661a5ced918eaa8ddb3807a1254cf90c9"
	recordKeyZeroLeafMaxKatHex = "ab16b8ff64ece9c345e02d642a530b6f6737b3a28ef2a650413ffc4636ca0752"
	recordKeyOneLeaf3KatHex    = "27311869389d0dd559d8c34b2889e07186d9209e7dd0cc65690d34d33c43fa3d"
	recordKeyTwoLeaf3KatHex    = "7cb481dc56a2b51c947e5e690b626af3b03ed1f77b98da1f5437253f940155fb"
	recordAeadHeadKeyKatHex    = "7dc5505c0942003dd1a34d15b5cf09aa1e5c05792f17d4be7d3145745de904db"
	recordAeadHeadNonceKatHex  = "bd3ad13ca235b86843e5fddd40b91fe9a122cad10b01d467"
	recordAeadBodyKeyKatHex    = "be6244d5c0f371e959cd6b7b72a481dd1aec0dcb7f6699e7ac5e4f4d68ddd20e"
	recordAeadBodyNonceKatHex  = "2c115e3d19ee0aa7f127ec652895e8b40ee77efa4c23db94"

	recordKeyZeroMinimalLpKatHex = "5fb5a37f2c471c0c92be05d0a2445b0d761b1d45eb7b5fd798b7687db70654d3"
)

// The leaf every multi-value vector above is taken at.
const recordKeyKatLeaf uint32 = 3

// The class key the vectors hang off, derived through the package rather than pasted, so a
// change to the class expansion is a failure here and not a silently stale constant.
func recordKeyKatClassKey() []byte {
	mlsSecret, pqSecret := keyScheduleKatInputs()
	return DeriveClassKeys(StorageRoot(mlsSecret, pqSecret)).Durable
}

// Property 1, the value half: the whole ladder is pinned, and the reference implementation
// agrees with every pin.
func TestRecordKeyLadderKAT(t *testing.T) {
	classKey := recordKeyKatClassKey()
	if string(classKey) != string(mustKeyScheduleHex(t, durableClassKeyKatHex)) {
		t.Fatalf("the class key this file hangs off is %x and keyschedule_test.go pins %x", classKey, durableClassKeyKatHex)
	}
	// record_key[0] over four leaves, including both ends of the u32
	for _, row := range []struct {
		leaf uint32
		hex  string
	}{
		{leaf: 0, hex: recordKeyZeroLeaf0KatHex},
		{leaf: 3, hex: recordKeyZeroLeaf3KatHex},
		{leaf: 7, hex: recordKeyZeroLeaf7KatHex},
		{leaf: 0xFFFFFFFF, hex: recordKeyZeroLeafMaxKatHex},
	} {
		want := mustKeyScheduleHex(t, row.hex)
		reference := keyScheduleReferenceExpand(classKey, append([]byte(recordKeyZeroInfo), recordKeyReferenceLP(row.leaf)...), 32)
		if string(reference) != string(want) {
			t.Fatalf("RFC 5869 written out here gives %x for record_key[0] at leaf %d and the pinned vector is %x", reference, row.leaf, want)
		}
		if got := RecordKeyZero(classKey, row.leaf); string(got) != string(want) {
			t.Errorf("RecordKeyZero(class_key, %d) = %x, want %x", row.leaf, got, want)
		}
	}
	// and the two rungs above it
	zero := RecordKeyZero(classKey, recordKeyKatLeaf)
	one := RecordKeyNext(zero)
	two := RecordKeyNext(one)
	for _, row := range []struct {
		what string
		got  []byte
		hex  string
	}{
		{what: "record_key[1]", got: one, hex: recordKeyOneLeaf3KatHex},
		{what: "record_key[2]", got: two, hex: recordKeyTwoLeaf3KatHex},
	} {
		want := mustKeyScheduleHex(t, row.hex)
		if string(row.got) != string(want) {
			t.Errorf("%s = %x, want %x", row.what, row.got, want)
		}
	}
	if got := keyScheduleReferenceExpand(zero, []byte(recordKeyNextInfo), 32); string(got) != string(one) {
		t.Errorf("RFC 5869 written out here gives %x for record_key[1] and the package gives %x", got, one)
	}
	// and the aead material, key and nonce, head and body
	headKey, headNonce := RecordAeadHead(zero)
	bodyKey, bodyNonce := RecordAeadBody(zero)
	for _, row := range []struct {
		what string
		got  []byte
		hex  string
	}{
		{what: "key_head", got: headKey, hex: recordAeadHeadKeyKatHex},
		{what: "nonce_head", got: headNonce, hex: recordAeadHeadNonceKatHex},
		{what: "key_body", got: bodyKey, hex: recordAeadBodyKeyKatHex},
		{what: "nonce_body", got: bodyNonce, hex: recordAeadBodyNonceKatHex},
	} {
		want := mustKeyScheduleHex(t, row.hex)
		if string(row.got) != string(want) {
			t.Errorf("%s = %x, want %x", row.what, row.got, want)
		}
	}
	reference := keyScheduleReferenceExpand(zero, []byte(recordAeadHeadInfo), 56)
	if string(reference[:32]) != string(headKey) || string(reference[32:]) != string(headNonce) {
		t.Errorf("RFC 5869 written out here splits rec/v1/head into %x and %x; the package gives %x and %x",
			reference[:32], reference[32:], headKey, headNonce)
	}
}

// The four octet reading of LP, written here rather than called from the package, so the vector
// above holds the package's encoding rather than restating it.
func recordKeyReferenceLP(leaf uint32) []byte {
	return append([]byte{0x00, 0x00, 0x00, 0x04}, binary.BigEndian.AppendUint32(nil, leaf)...)
}

// Property 5, the half no round trip can see: WHICH reading of LP(leaf_index) record_key[0]
// takes.
//
// Both readings produce thirty two octets from the same class key and the same leaf, so nothing
// inside one implementation can tell them apart -- only a vector can, and only a vector that
// pins BOTH. Open item M1-8 is wire visible and blocks the A6 freeze; when it is ruled, the
// value that has to change is one of these two.
func TestRecordKeyZeroTakesTheFourOctetReadingOfLP(t *testing.T) {
	classKey := recordKeyKatClassKey()
	fourOctet := mustKeyScheduleHex(t, recordKeyZeroLeaf3KatHex)
	minimal := mustKeyScheduleHex(t, recordKeyZeroMinimalLpKatHex)
	if string(fourOctet) == string(minimal) {
		t.Fatal("the two readings of LP(leaf_index) pin the same octets, so this test cannot tell them apart")
	}
	// the minimal reading, written out here: the length 00 00 00 01 then the one octet index
	reference := keyScheduleReferenceExpand(classKey,
		append([]byte(recordKeyZeroInfo), 0x00, 0x00, 0x00, 0x01, byte(recordKeyKatLeaf)), 32)
	if string(reference) != string(minimal) {
		t.Fatalf("the minimal reading written out here gives %x and the pinned alternative is %x", reference, minimal)
	}
	got := RecordKeyZero(classKey, recordKeyKatLeaf)
	if string(got) != string(fourOctet) {
		t.Errorf("RecordKeyZero took a reading of LP(leaf_index) this file does not pin: %x", got)
	}
	if string(got) == string(minimal) {
		t.Error("RecordKeyZero length prefixes the MINIMAL encoding of the leaf index; sender_handle takes the four octet reading and the two derivations must not disagree")
	}
}

// Property 1, the structural half: the ladder is a chain, it is reproducible, and no two
// positions inside it collide.
//
// Two thousand and forty eight positions and not two, because a chain that returned its input
// would be caught by any adjacent pair and a chain that cycled would not.
func TestTheRecordKeyLadderIsAChainWithNoRepeatedRung(t *testing.T) {
	const rungs = 2048
	classKey := recordKeyKatClassKey()
	seen := map[string]int{}
	walk := func() [][]byte {
		ladder := [][]byte{RecordKeyZero(classKey, recordKeyKatLeaf)}
		for position := 1; position < rungs; position += 1 {
			ladder = append(ladder, RecordKeyNext(ladder[position-1]))
		}
		return ladder
	}
	first := walk()
	second := walk()
	for position, rung := range first {
		if len(rung) != recordKeyBytes {
			t.Fatalf("record_key[%d] is %d octets, want %d", position, len(rung), recordKeyBytes)
		}
		if string(rung) != string(second[position]) {
			t.Fatalf("two walks of the ladder disagree at position %d, so the derivation is not a function of the class key and the leaf", position)
		}
		if earlier, isRepeat := seen[string(rung)]; isRepeat {
			t.Fatalf("record_key[%d] and record_key[%d] are the same octets; a repeated rung is a repeated aead key and a repeated nonce", earlier, position)
		}
		seen[string(rung)] = position
	}
}

// Property 3: the fifty six octets split into a thirty two octet key and a twenty four octet
// nonce, at those offsets, and the four values one rung produces are pairwise distinct.
func TestTheAeadMaterialSplitsFiftySixIntoAKeyAndAnExtendedNonce(t *testing.T) {
	// the width is DERIVED from the primitive and not written down, which is what makes a
	// suite change a compile error rather than a silently truncated nonce
	if recordAeadMaterialBytes != chacha20poly1305.KeySize+chacha20poly1305.NonceSizeX {
		t.Fatalf("the material width is %d and the primitive gives %d + %d", recordAeadMaterialBytes, chacha20poly1305.KeySize, chacha20poly1305.NonceSizeX)
	}
	if recordAeadMaterialBytes != 56 {
		t.Errorf("MASTER section 8.1 gives 56 for key_head | nonce_head and this build derives %d", recordAeadMaterialBytes)
	}
	classKey := recordKeyKatClassKey()
	rung := RecordKeyZero(classKey, recordKeyKatLeaf)
	material := keyScheduleReferenceExpand(rung, []byte(recordAeadHeadInfo), recordAeadMaterialBytes)
	headKey, headNonce := RecordAeadHead(rung)
	bodyKey, bodyNonce := RecordAeadBody(rung)
	if len(headKey) != chacha20poly1305.KeySize || len(bodyKey) != chacha20poly1305.KeySize {
		t.Errorf("the keys are %d and %d octets, want %d", len(headKey), len(bodyKey), chacha20poly1305.KeySize)
	}
	if len(headNonce) != chacha20poly1305.NonceSizeX || len(bodyNonce) != chacha20poly1305.NonceSizeX {
		t.Errorf("the nonces are %d and %d octets, want %d", len(headNonce), len(bodyNonce), chacha20poly1305.NonceSizeX)
	}
	// the OFFSETS, which is the half a width check cannot see: the key is the first thirty
	// two octets and the nonce is the last twenty four, and a transposition produces two
	// values of the right widths that seal and open against themselves
	if string(headKey) != string(material[:chacha20poly1305.KeySize]) {
		t.Errorf("key_head is not the FIRST %d octets of the expansion", chacha20poly1305.KeySize)
	}
	if string(headNonce) != string(material[chacha20poly1305.KeySize:]) {
		t.Errorf("nonce_head is not the LAST %d octets of the expansion", chacha20poly1305.NonceSizeX)
	}
	// and an append to one half must not reach the other, which is what the capacity cut is
	// for: without it a caller growing the key writes into the nonce's octets
	grown := append(headKey, 0xFF)
	if string(headNonce) != string(material[chacha20poly1305.KeySize:]) {
		t.Errorf("appending to key_head changed nonce_head; the two halves share a backing array with room to spill")
	}
	_ = grown
	// the four values are pairwise distinct
	values := map[string]string{
		"key_head":   string(headKey),
		"nonce_head": string(headNonce),
		"key_body":   string(bodyKey),
		"nonce_body": string(bodyNonce),
	}
	names := slices.Sorted(maps.Keys(values))
	for i, left := range names {
		for _, right := range names[i+1:] {
			if values[left] == values[right] {
				t.Errorf("%s and %s are the same octets", left, right)
			}
		}
	}
	// and the head's key is not the body's key: a record whose two ciphertexts share a key
	// and a nonce is a record whose Poly1305 one time key an attacker recovers
	if string(headKey) == string(bodyKey) && string(headNonce) == string(bodyNonce) {
		t.Error("the head and the body derive one key and one nonce")
	}
}

// Property 4: the four labels of the ladder are four constants, and none of them is built out of
// another by concatenation.
//
// The CLASS is derived off the syntax tree and is not the four names this task added: every
// package level string constant of this package's production source whose value this package
// hands to keyScheduleExpand as an info. A fifth label arriving with a shared stem is judged by
// this gate without anybody extending it.
//
// The pair this exists for is rec/v1/head and rec/v1/body, which agree over eleven of their
// fifteen characters. A single constant with the tail substituted is one edit from handing a
// record's head and body one key and one nonce, and the class labels next door are written under
// the same rule for the same reason.
func TestTheLadderLabelsAreSeparateConstantsAndNoneIsBuiltFromAnother(t *testing.T) {
	_, sources := messagegroupProductionSources(t)
	constants := keyScheduleStringConstantsOf(sources)
	// The derived class: every string constant this package hands to something that reaches
	// the kdf. It is TRANSITIVE rather than a check on the arguments of keyScheduleExpand
	// itself, and the difference is measured: rec/v1/head and rec/v1/body are passed to
	// recordAeadMaterial, which is what expands, and a one-hop reading found neither of the
	// two labels this gate exists for.
	reaching := recordKeyKdfReachingFunctions(sources)
	infoNames := map[string]bool{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, isCall := node.(*ast.CallExpr)
				if !isCall {
					return true
				}
				callee, isName := call.Fun.(*ast.Ident)
				if !isName || !reaching[callee.Name] {
					return true
				}
				for _, argument := range call.Args {
					for _, named := range keyScheduleIdentifiersIn(argument) {
						if _, isConstant := constants[named]; isConstant {
							infoNames[named] = true
						}
					}
				}
				return true
			})
		}
	}
	labels := slices.Sorted(maps.Keys(infoNames))
	if len(labels) == 0 {
		t.Fatal("no string constant of this package reaches an expansion as an info, so this gate held no label to anything")
	}
	for _, wanted := range []string{"recordAeadBodyInfo", "recordAeadHeadInfo", "recordKeyNextInfo", "recordKeyZeroInfo"} {
		if !slices.Contains(labels, wanted) {
			t.Errorf("%s is a label of the ladder and this gate's derived class did not reach it: %v", wanted, labels)
		}
	}
	for i, left := range labels {
		for _, right := range labels[i+1:] {
			if constants[left] == constants[right] {
				t.Errorf("%s and %s are the same label %q; two derivations under one label are one key", left, right, constants[left])
			}
			if strings.HasPrefix(constants[left], constants[right]) || strings.HasPrefix(constants[right], constants[left]) {
				// a shared prefix is legal -- rec/v1/head and rec/v1/body have one -- but
				// one label being the WHOLE of another means a truncation makes them equal
				t.Errorf("%s (%q) is the whole of %s (%q); a truncation of the longer one is the shorter one",
					left, constants[left], right, constants[right])
			}
		}
	}
	// and no label is BUILT: every one of them is a plain literal in a const declaration,
	// which keyScheduleStringConstantsOf is what says, and no expansion's info argument is a
	// concatenation of two of them
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, isCall := node.(*ast.CallExpr)
				if !isCall {
					return true
				}
				callee, isName := call.Fun.(*ast.Ident)
				if !isName || callee.Name != "keyScheduleExpand" {
					return true
				}
				if len(call.Args) < 2 {
					return true
				}
				labelled := 0
				for _, named := range keyScheduleIdentifiersIn(call.Args[1]) {
					if infoNames[named] {
						labelled += 1
					}
				}
				if 1 < labelled {
					t.Errorf("%s expands under an info naming %d of this package's labels at once; one info is one label",
						function.Name.Name, labelled)
				}
				return true
			})
		}
	}
}

// Property 5: record_key[0] binds the leaf, and it binds it through the one helper.
func TestRecordKeyZeroSeparatesEveryLeafAndGoesThroughTheOneHelper(t *testing.T) {
	classKey := recordKeyKatClassKey()
	seen := map[string]uint32{}
	for _, leaf := range []uint32{0, 1, 2, 3, 7, 63, 64, 4095, 0xFFFFFFFE, 0xFFFFFFFF} {
		rung := RecordKeyZero(classKey, leaf)
		if earlier, isRepeat := seen[string(rung)]; isRepeat {
			t.Errorf("leaves %d and %d start the same ladder", earlier, leaf)
		}
		seen[string(rung)] = leaf
		// and the binding is the helper's encoding rather than a second one
		want := keyScheduleReferenceExpand(classKey, append([]byte(recordKeyZeroInfo), leafIndexLP(leaf)...), recordKeyBytes)
		if string(rung) != string(want) {
			t.Errorf("RecordKeyZero at leaf %d is not HKDF-Expand(class_key, \"sender/v1\" | leafIndexLP(leaf), 32)", leaf)
		}
	}
	// and two class keys separate two ladders at the same leaf, which is what makes a
	// retention class a retention class
	other := DeriveClassKeys(StorageRoot(keyScheduleKatInputs())).Perm
	if string(RecordKeyZero(classKey, recordKeyKatLeaf)) == string(RecordKeyZero(other, recordKeyKatLeaf)) {
		t.Error("the durable and permanent class keys start the same ladder at one leaf")
	}
}

// Property 6: a class key or a record key of the wrong width is refused rather than expanded.
//
// The refusal is a panic carrying the sentinel because the signatures spec A section 5.3
// publishes have no error to return. Every width but the right one is refused, in both
// directions: a LONG key is as wrong as a short one and is the shape a value decoded out of
// durable storage takes.
func TestTheLadderRefusesAKeyOfTheWrongWidth(t *testing.T) {
	classKey := recordKeyKatClassKey()
	rung := RecordKeyZero(classKey, recordKeyKatLeaf)
	for _, width := range []int{0, 1, 16, 31, 33, 56, 64} {
		wrong := make([]byte, width)
		for _, refusal := range []struct {
			name     string
			sentinel error
			call     func()
		}{
			{name: "RecordKeyZero", sentinel: ErrClassKeyLength, call: func() { RecordKeyZero(wrong, 3) }},
			{name: "RecordKeyNext", sentinel: ErrRecordKeyLength, call: func() { RecordKeyNext(wrong) }},
			{name: "RecordAeadHead", sentinel: ErrRecordKeyLength, call: func() { RecordAeadHead(wrong) }},
			{name: "RecordAeadBody", sentinel: ErrRecordKeyLength, call: func() { RecordAeadBody(wrong) }},
		} {
			caught := handleRecoveredFrom(refusal.call)
			if caught == nil {
				t.Errorf("%s accepted a %d octet key; a key of the wrong width expands to a well formed rung no peer computes", refusal.name, width)
				continue
			}
			if !errors.Is(caught, refusal.sentinel) {
				t.Errorf("%s refused a %d octet key with %v, want %v", refusal.name, width, caught, refusal.sentinel)
			}
		}
	}
	// and the right width is not refused
	for _, accepted := range []struct {
		name string
		call func()
	}{
		{name: "RecordKeyZero", call: func() { RecordKeyZero(classKey, 3) }},
		{name: "RecordKeyNext", call: func() { RecordKeyNext(rung) }},
		{name: "RecordAeadHead", call: func() { RecordAeadHead(rung) }},
		{name: "RecordAeadBody", call: func() { RecordAeadBody(rung) }},
	} {
		if caught := handleRecoveredFrom(accepted.call); caught != nil {
			t.Errorf("%s refused a thirty two octet key with %v", accepted.name, caught)
		}
	}
	// and the storage root and class key refusals one derivation up, which had no width
	// check at all until this batch: a root LONGER than thirty two was accepted in silence
	for _, width := range []int{0, 31, 33, 64} {
		wrong := make([]byte, width)
		for _, refusal := range []struct {
			name string
			call func()
		}{
			{name: "GroupHandleKey", call: func() { GroupHandleKey(wrong) }},
			{name: "DeriveClassKeys", call: func() { DeriveClassKeys(wrong) }},
		} {
			caught := handleRecoveredFrom(refusal.call)
			if caught == nil {
				t.Errorf("%s accepted a %d octet storage root", refusal.name, width)
				continue
			}
			if !errors.Is(caught, ErrStorageRootLength) {
				t.Errorf("%s refused a %d octet storage root with %v, want ErrStorageRootLength", refusal.name, width, caught)
			}
		}
	}
}

// Property 2: nothing this package exports leads BACKWARDS along the ladder.
//
// The CLASS is derived and the scope question (R3a) is answered separately from it. The class is
// every exported declaration of this package's production source that reaches an expansion or an
// extraction -- transitively, through this package's own calls -- which is exactly "the key
// schedule surface" and is not the two names this task added. The scope is this directory,
// because the property is about what THIS package publishes.
//
// Each member owes a row giving a probe: a function that, handed record_key[i+1] wherever it
// takes a secret, returns every byte string it produces. The assertion is that no probe's output
// is record_key[i], for every i in a range -- so a member that inverted a rung, or that returned
// its own input, or that answered a value the ladder had already passed, fails here whatever it
// is called.
//
// A member with no row is an error and a row with no member is an error, so the table cannot
// outlive its subject in either direction. An empty class is fatal: a derivation that stopped
// reaching the package would clear this property having read nothing.
var recordKeyOneWayProbes = map[string]func(secret []byte) [][]byte{
	"StorageRoot": func(secret []byte) [][]byte {
		return [][]byte{StorageRoot(secret, secret), StorageRoot(secret, make([]byte, 32))}
	},
	"DeriveClassKeys": func(secret []byte) [][]byte {
		keys := DeriveClassKeys(secret)
		return [][]byte{keys.Perm, keys.Durable, keys.Media}
	},
	"GroupHandleKey": func(secret []byte) [][]byte { return [][]byte{GroupHandleKey(secret)} },
	"SenderHandle": func(secret []byte) [][]byte {
		handle := SenderHandle(secret, recordKeyKatLeaf)
		return [][]byte{handle[:]}
	},
	"WrapTargetHandle": func(secret []byte) [][]byte {
		handle := WrapTargetHandle(secret, 1, recordKeyKatLeaf)
		return [][]byte{handle[:]}
	},
	"RecordKeyZero": func(secret []byte) [][]byte {
		return [][]byte{RecordKeyZero(secret, recordKeyKatLeaf), RecordKeyZero(secret, 0)}
	},
	"RecordKeyNext": func(secret []byte) [][]byte { return [][]byte{RecordKeyNext(secret)} },
	"RecordAeadHead": func(secret []byte) [][]byte {
		key, nonce := RecordAeadHead(secret)
		return [][]byte{key, nonce}
	},
	"RecordAeadBody": func(secret []byte) [][]byte {
		key, nonce := RecordAeadBody(secret)
		return [][]byte{key, nonce}
	},
	"NewSenderRatchet": func(secret []byte) [][]byte {
		ratchet, err := NewSenderRatchet(secret, recordKeyKatLeaf, []byte("one-way"), newStreamIndexMemory())
		if err != nil {
			return nil
		}
		_, key, err := ratchet.Next()
		if err != nil {
			return nil
		}
		return [][]byte{key}
	},
	"Next": func(secret []byte) [][]byte {
		ratchet, err := NewSenderRatchet(secret, recordKeyKatLeaf, []byte("one-way"), newStreamIndexMemory())
		if err != nil {
			return nil
		}
		produced := [][]byte{}
		for range 3 {
			_, key, err := ratchet.Next()
			if err != nil {
				return produced
			}
			produced = append(produced, key)
		}
		return produced
	},
	"NewReceiverRatchet": func(secret []byte) [][]byte {
		ratchet, err := NewReceiverRatchet(secret, recordKeyKatLeaf, 0, 8)
		if err != nil {
			return nil
		}
		key, err := ratchet.KeyFor(0)
		if err != nil {
			return nil
		}
		return [][]byte{key}
	},
	"KeyFor": func(secret []byte) [][]byte {
		ratchet, err := NewReceiverRatchet(secret, recordKeyKatLeaf, 0, 8)
		if err != nil {
			return nil
		}
		produced := [][]byte{}
		for index := uint64(0); index < 3; index += 1 {
			key, err := ratchet.KeyFor(index)
			if err != nil {
				return produced
			}
			produced = append(produced, key)
		}
		return produced
	},
}

func TestNothingExportedLeadsBackwardsAlongTheLadder(t *testing.T) {
	_, sources := messagegroupProductionSources(t)
	members := recordKeyScheduleSurface(sources)
	if len(members) == 0 {
		t.Fatal("no exported declaration of this package reaches an expansion or an extraction, so this gate cleared the whole key schedule having found nothing to judge")
	}
	for _, name := range members {
		if _, hasRow := recordKeyOneWayProbes[name]; !hasRow {
			t.Errorf("%s reaches the key schedule and recordKeyOneWayProbes has no row for it; every published derivation owes the one way property a probe", name)
		}
	}
	for name := range recordKeyOneWayProbes {
		if !slices.Contains(members, name) {
			t.Errorf("recordKeyOneWayProbes has a row for %s, which no longer reaches the key schedule; a row that outlived its subject reads as coverage", name)
		}
	}
	classKey := recordKeyKatClassKey()
	ladder := [][]byte{RecordKeyZero(classKey, recordKeyKatLeaf)}
	for position := 1; position < 8; position += 1 {
		ladder = append(ladder, RecordKeyNext(ladder[position-1]))
	}
	behind := map[string]int{}
	for position, rung := range ladder {
		behind[string(rung)] = position
	}
	for _, name := range members {
		probe, hasRow := recordKeyOneWayProbes[name]
		if !hasRow {
			continue
		}
		for position := 1; position < len(ladder); position += 1 {
			for _, produced := range probe(ladder[position]) {
				earlier, isRung := behind[string(produced)]
				if isRung && earlier <= position {
					t.Errorf("%s handed record_key[%d] answered record_key[%d]; the ladder is meant to be one way and this is a rung it has already passed",
						name, position, earlier)
				}
			}
		}
	}
}

// recordKeyScheduleSurface derives the exported declarations that reach this package's one
// expansion or its one extraction, transitively through calls declared in this package.
//
// It is a fixed point rather than one hop, because a derivation reached through a helper is as
// published as one that spells the call: NewSenderRatchet reaches keyScheduleExpand through
// RecordKeyZero and is exactly as much a way to obtain a rung.
//
// A method is named by its own name, which can only WIDEN the class -- two methods sharing a
// name are one entry and the probe must satisfy both -- and a wider class demands a row of more
// declarations rather than fewer, which is the direction a gate may be wrong in.
func recordKeyScheduleSurface(sources []messagegroupSource) []string {
	reaching := recordKeyKdfReachingFunctions(sources)
	members := []string{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			name := function.Name.Name
			if ast.IsExported(name) && reaching[name] && !slices.Contains(members, name) {
				members = append(members, name)
			}
		}
	}
	slices.Sort(members)
	return members
}

// recordKeyKdfReachingFunctions is every function this package declares that reaches its one
// expansion or its one extraction, closed under this package's own calls to a fixed point.
//
// There is no seed written down beyond the two helpers themselves, which are the only doors onto
// the kdf this package has -- keyschedule_test.go's extraction gate and imports_test.go together
// are what keep that true -- so a derivation reached through any chain of helpers is a member
// without anybody naming the chain.
func recordKeyKdfReachingFunctions(sources []messagegroupSource) map[string]bool {
	return messagegroupFunctionsReaching(sources, []string{"keyScheduleExpand", "keyScheduleExtract"})
}

// messagegroupFunctionsReaching closes a set of seed names under "calls a member", over this
// package's own declarations, to a fixed point.
//
// It is the shape every "reaches X" question in this package's suite is answered with, so a
// derivation reached through a chain of helpers is a member without anybody naming the chain --
// which is the difference between a class and a list.
func messagegroupFunctionsReaching(sources []messagegroupSource, seeds []string) map[string]bool {
	calls := map[string][]string{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			name := function.Name.Name
			calls[name] = append(calls[name], keyScheduleCalleeNames(function.Body)...)
		}
	}
	reaching := map[string]bool{}
	for _, seed := range seeds {
		reaching[seed] = true
	}
	for grew := true; grew; {
		grew = false
		for name, callees := range calls {
			if reaching[name] {
				continue
			}
			for _, callee := range callees {
				if reaching[callee] {
					reaching[name] = true
					grew = true
					break
				}
			}
		}
	}
	return reaching
}
