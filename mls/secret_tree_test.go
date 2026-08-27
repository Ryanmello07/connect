// tests for the RFC 9420 section 9 secret tree: the descent, and the deletions that are
// the forward secrecy.
//
// Half of this file asks what a value IS, and that half is cheap: every implementation of
// section 9 that derives correctly agrees on it, including one that never deletes anything.
// The other half asks what is NO LONGER REACHABLE, which is the property the section exists
// for and the one nothing else in this package has needed yet. Where that question runs into
// what go can actually observe — a copy the runtime made, a value left in a register — the
// limit is written down in the comment rather than papered over with an assertion that would
// pass either way.
//
// What the plan's own six tests were measured unable to fail, run verbatim against fifteen
// single-edit mutants of secret_tree.go, each mutant confirmed applied by diff before its
// result was believed:
//
//   - TestSecretTreeLeafCount never failed against any of the fifteen. It builds one tree of
//     eight leaves and asks for eight back, so an accessor whose body is "return 8" satisfies
//     it. Replaced here by a sweep over every swept width, which fails against exactly that
//     mutant.
//   - TestSecretTreeRejectsOutOfRangeLeaf never failed against any of the fifteen, INCLUDING
//     the one that deletes the leaf-count range check outright. Its two probes, 8 and 1<<20,
//     are both refused by the node-array bound instead, so the check it exists to exercise can
//     be removed with the test still green -- and with it removed, leaf 2^31 wraps to node 0
//     and the tree hands out leaf 0's secret to a sender claiming an index no tree can hold.
//     The version here probes 1<<31, (1<<31)+4 and 0xffffffff, and fails against that mutant.
//   - TestSecretTreeDescentDerivesBothChildren does fail against a swapped label and a mirrored
//     descent, but not against the erasure moved one step too early -- the mutation its own
//     last assertion names. "leaf 7 is still reachable" is checked as err == nil, and a right
//     subtree derived from a run of zeros is still perfectly reachable. The version here
//     compares leaf 7's bytes.
//   - TestSecretTreeLeafSecretIsTakenOnce sees the map delete but not the erasure: it passes
//     against a tree that never calls zeroizeSecret at all, which is the half of the forward
//     secrecy claim in its own doc comment that it does not observe.
//
// No plan test failed against any of: never zeroizing a node secret, hardcoding the KDF width
// to 32, ignoring Root's error, or hardcoding the node-array width.
//
// A second round of measurement, over the file as it then stood, found the SCOPE of the two
// forward secrecy tests to be the defect rather than their assertions. Both asked what remains
// by naming the field tree.nodes, so a SecretTree that kept an un-zeroized copy of every
// destroyed node secret in a SECOND field passed all 750 tests of this tree -- the exact
// negation of the property this file exists for, and not hypothetical: p4 task 22 adds a
// second secret bearing field to this very struct. What replaces the field name is
// secretTreeRetainedBytes, which derives "what the tree still holds" from the TYPE, and the
// four further mutants that round measured as surviving are answered by
// TestSecretTreeCachedGeometryIsDerivedFromTheLeafCount (a width or a depth that is not the
// leaf count's) and TestSecretTreeTakesTheDeepestHeldAncestorAndNotTheShallowest. The two
// that remain unkillable are unreachable rather than unobserved, are labelled as such in
// secret_tree.go, and each has the invariant that makes it unreachable asserted here:
// TestSecretTreePathToLeafLandsOnTheTargetOfEveryLeafOfEveryWidth for the post descent landing
// check, and TestSecretTreeASecondTakeIsAlwaysTheConsumedRefusalAndNeverTheInvariantOne for
// the post loop consumed return.
package mls

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

// stTestCrypto returns the ciphersuite 0x0003 provider the secret tree KATs use.
func stTestCrypto(t *testing.T) CryptoProvider {
	t.Helper()
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	return crypto
}

const stVectorEncryptionSecret = "59227ed552e4a6db0779d43aea694fd1b2c2540e605a099b95cf852b41e8ea66"

// stSweptLeafCounts is every full leaf count this file sweeps. It is written as a range
// rather than a list so that "the sizes covered" is a bound and not a set somebody has to
// keep in step with the assertions: every power of two from one leaf to sixty-four.
func stSweptLeafCounts() []LeafCount {
	counts := []LeafCount{}
	for n := LeafCount(1); n <= 64; n *= 2 {
		counts = append(counts, n)
	}
	return counts
}

// stLeavesOf returns the leaf indices of a tree, derived from its node array's width rather
// than picked. Leaves are the even node indices below the width, so this is the same set the
// implementation has to reach and it is obtained from tree math rather than from a literal.
//
// The node to leaf step is p3's NodeIndex.LeafIndex and not a node/2 written here. The two
// agree on every even index and disagree on every odd one -- p3's REFUSES a parent index and
// a local division silently truncates it to the leaf on its left -- so a width that ever
// started at an odd node, or a step that stopped being two, is a failure here rather than a
// leaf set that looks the right size and names the wrong leaves.
func stLeavesOf(t *testing.T, leafCount LeafCount) []LeafIndex {
	t.Helper()
	width := NodeWidth(leafCount)
	if width == 0 {
		t.Fatalf("NodeWidth(%d) is zero, so this sweep would cover nothing", leafCount)
	}
	leaves := []LeafIndex{}
	for node := uint32(0); node < width; node += 2 {
		leaf, err := NodeIndex(node).LeafIndex()
		if err != nil {
			t.Fatalf("NodeIndex(%d).LeafIndex(): %v", node, err)
		}
		leaves = append(leaves, leaf)
	}
	if LeafCount(len(leaves)) != leafCount {
		t.Fatalf("width %d yields %d leaves for a count of %d", width, len(leaves), leafCount)
	}
	return leaves
}

// stExpectedNodeSecret derives one node's secret from the encryption secret independently of
// the code under test.
//
// It shares no arithmetic with the descent. pathToLeaf decides direction by comparing the
// target index against the node it is standing on; this walks p3's DirectPath UPWARD to
// learn the ancestry, replays it downward, and asks Left and Right at each step which child
// the next node actually is. So a descent that went to the sibling, or that labelled the
// left child "right", disagrees with this and cannot disagree with it in the same direction.
//
// The expansion length is read off the provider for the same reason the implementation reads
// it: both registered suites fix Nh at 32, so a literal here would agree with a literal there
// and the pair would be wrong together.
func stExpectedNodeSecret(t *testing.T, crypto CryptoProvider, encryptionSecret []byte,
	leafCount LeafCount, node NodeIndex) []byte {
	t.Helper()
	upward, err := DirectPath(node, leafCount)
	if err != nil {
		t.Fatalf("DirectPath(%d, %d): %v", node, leafCount, err)
	}
	chain := make([]NodeIndex, 0, len(upward)+1)
	for i := len(upward) - 1; i >= 0; i-- {
		chain = append(chain, upward[i])
	}
	chain = append(chain, node)
	root, err := Root(leafCount)
	if err != nil {
		t.Fatalf("Root(%d): %v", leafCount, err)
	}
	if chain[0] != root {
		t.Fatalf("the replay starts at node %d, want the root %d", chain[0], root)
	}
	secret := append([]byte(nil), encryptionSecret...)
	for i := 0; i+1 < len(chain); i++ {
		parent, child := chain[i], chain[i+1]
		left, err := Left(parent)
		if err != nil {
			t.Fatalf("Left(%d): %v", parent, err)
		}
		right, err := Right(parent)
		if err != nil {
			t.Fatalf("Right(%d): %v", parent, err)
		}
		switch child {
		case left:
			secret = crypto.ExpandWithLabel(secret, "tree", []byte("left"), crypto.HashSize())
		case right:
			secret = crypto.ExpandWithLabel(secret, "tree", []byte("right"), crypto.HashSize())
		default:
			t.Fatalf("node %d is neither child of %d", child, parent)
		}
	}
	return secret
}

// ---------------------------------------------------------------------------
// what the tree still holds, derived from its type rather than from a field name
// ---------------------------------------------------------------------------

// secretTreeHeld is one byte bearing value a SecretTree still reaches, named by the path
// reflect walked to get to it.
type secretTreeHeld struct {
	where   string
	carried []byte
}

// secretTreeByteWalk is one walk in progress: what it has read, what it declined to read,
// and the pointers and maps it has already been through.
type secretTreeByteWalk struct {
	held     []secretTreeHeld
	unwalked []string
	seen     map[uintptr]bool
}

// secretTreeWalkDepthLimit bounds the walk so a cyclic shape the seen set does not cover --
// a slice holding itself, say -- reports rather than hangs. It is far past the depth of
// anything this package declares.
const secretTreeWalkDepthLimit = 24

// secretTreeIntegerRun reads a slice or array of a fixed width integer kind as one buffer of
// its elements' little endian bytes, and reports whether the element kind was one.
//
// It exists so that a secret held as []byte and a secret held as []uint32 -- or as [32]byte,
// which is neither -- are read the same way, rather than the first being read and the other
// two falling through a case written for byte slices. The bytes are copied out one element at
// a time because reflect refuses Bytes and Interface on a value reached through an unexported
// field; Uint and Int on an element are permitted, are reads and not handles, and need no
// unsafe.
func secretTreeIntegerRun(value reflect.Value) ([]byte, bool) {
	element := value.Type().Elem()
	signed := false
	switch element.Kind() {
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint, reflect.Uintptr:
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Int:
		signed = true
	default:
		return nil, false
	}
	width := int(element.Size())
	out := make([]byte, 0, value.Len()*width)
	for at := range value.Len() {
		held := uint64(0)
		if signed {
			held = uint64(value.Index(at).Int())
		} else {
			held = value.Index(at).Uint()
		}
		for octet := range width {
			out = append(out, byte(held>>(8*octet)))
		}
	}
	return out, true
}

// at walks one value, recording the bytes it carries and reporting anything it could not walk
// at all.
//
// The kinds are handled as a class rather than as the shapes SecretTree happens to have
// today, which is the whole point of the helper this belongs to: a gate that reads the field
// named nodes reads nothing about a second field, and the reason to derive is that a second
// field is coming. Strings are read because a secret held in one is held no less. Scalars
// carry nothing that could hold a node secret and say so below. Anything left -- a chan, a
// func, an unsafe pointer -- is REPORTED rather than skipped, so a field of a kind this walk
// was not written for fails the gate instead of quietly leaving the walk smaller than the
// type it is meant to cover.
func (self *secretTreeByteWalk) at(where string, value reflect.Value, depth int) {
	if depth > secretTreeWalkDepthLimit {
		self.unwalked = append(self.unwalked, where+" is deeper than this walk goes")
		return
	}
	switch value.Kind() {
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice && value.IsNil() {
			return
		}
		if run, ok := secretTreeIntegerRun(value); ok {
			self.held = append(self.held, secretTreeHeld{where: where, carried: run})
			return
		}
		for at := range value.Len() {
			self.at(fmt.Sprintf("%s[%d]", where, at), value.Index(at), depth+1)
		}
	case reflect.String:
		self.held = append(self.held, secretTreeHeld{where: where, carried: []byte(value.String())})
	case reflect.Struct:
		for at := range value.NumField() {
			self.at(where+"."+value.Type().Field(at).Name, value.Field(at), depth+1)
		}
	case reflect.Pointer, reflect.Interface:
		if value.IsNil() {
			return
		}
		if value.Kind() == reflect.Pointer {
			if self.seen[value.Pointer()] {
				return
			}
			self.seen[value.Pointer()] = true
		}
		self.at(where+"->", value.Elem(), depth+1)
	case reflect.Map:
		if value.IsNil() {
			return
		}
		if self.seen[value.Pointer()] {
			return
		}
		self.seen[value.Pointer()] = true
		// KEYS as well as values: a table that remembered a destroyed secret by keying on it
		// holds that secret exactly as much as one that stored it. Sorted by the rendering
		// providerStructByteFields sorts by, because go randomises map iteration on purpose
		// and a walk that reported one value two different ways would make every count
		// derived from it flap.
		keys := value.MapKeys()
		slices.SortFunc(keys, func(a reflect.Value, b reflect.Value) int {
			return strings.Compare(secretTreeMapKeyOrder(a), secretTreeMapKeyOrder(b))
		})
		for _, key := range keys {
			rendered := secretTreeMapKeyOrder(key)
			self.at(where+"{"+rendered+"}", key, depth+1)
			self.at(where+"["+rendered+"]", value.MapIndex(key), depth+1)
		}
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		// a scalar is narrower than one node secret and cannot hold one. The claim is checked
		// rather than asserted: secretTreeRetainedBytes refuses a provider whose hash size
		// would fit inside a scalar, so this sentence cannot go quietly stale.
	default:
		self.unwalked = append(self.unwalked,
			where+" is a "+value.Kind().String()+" of type "+value.Type().String())
	}
}

// secretTreeMapKeyOrder renders one map key for the walk's ordering, widening
// providerMapKeyOrder over STRUCT keys.
//
// providerMapKeyOrder answers a struct with its type name, which is one string for every key
// of the map -- so the sort below has nothing to separate them by, and go randomises map
// iteration on purpose. p4 task 22's ratchets map is keyed by a struct, so without this the
// walk over a SecretTree reports its values in a different order on every run and every count
// derived from it flaps. The fields are read with reflect rather than through Interface,
// which panics on a value reached through an unexported field.
func secretTreeMapKeyOrder(key reflect.Value) string {
	if key.Kind() != reflect.Struct {
		return providerMapKeyOrder(key)
	}
	rendered := []string{key.Type().String()}
	for at := range key.NumField() {
		rendered = append(rendered, secretTreeMapKeyOrder(key.Field(at)))
	}
	return strings.Join(rendered, "/")
}

// secretTreeWalkOf reads every byte a value reaches, and reports what it could not walk.
func secretTreeWalkOf(value reflect.Value) ([]secretTreeHeld, []string) {
	walk := &secretTreeByteWalk{seen: map[uintptr]bool{}}
	walk.at(value.Type().String(), value, 0)
	return walk.held, walk.unwalked
}

// secretTreeRetainedBytes is every byte a SecretTree still reaches, derived from its TYPE.
//
// This is the scope both forward secrecy tests below take "what remains" to mean, and it is
// written this way because the version that read tree.nodes was measured wrong. A SecretTree
// carrying an archive map[NodeIndex][]byte, filled with a copy of every parent secret one
// line before that parent is zeroized, keeps every ancestor of every consumed leaf alive for
// the whole epoch -- and passed all 750 tests of this package byte for byte, because both
// tests asked one named field what it held. p4 task 22 adds ratchets map[ratchetKey]*ratchet
// to this struct and each ratchet holds a secret, so the second secret bearing field is not a
// thought experiment; it is the next commit.
//
// The honest limit, stated at the same length as the claim. This reads what the IMPLEMENTATION
// still reaches, which is what go can observe and what an implementation can choose. It cannot
// observe a copy the RUNTIME made -- a growth that moved an array, a spill to a stack frame
// that is now garbage, a value still in a register -- and no go program can; secret_zeroize.go
// says the same thing at length. The comment these tests used to carry named only that second
// limit, which is true and was never the one that mattered: a copy the implementation kept is
// the one go observes trivially, and it was the one nothing looked for.
func secretTreeRetainedBytes(t *testing.T, tree *SecretTree) []secretTreeHeld {
	t.Helper()
	if tree == nil {
		t.Fatal("no tree to read, so this walk would report an empty retained state for the best reason and the worst one alike")
	}
	// the scalar claim in at(), checked rather than trusted: if a provider's hash size ever
	// fit inside one scalar, "a scalar cannot hold a node secret" would be false and this
	// walk would be skipping a container that could hold one.
	if nh := tree.crypto.HashSize(); nh <= 8 {
		t.Fatalf("the provider's hash size is %d bytes, which fits inside one scalar; this walk skips scalars on the grounds that it does not", nh)
	}
	held, unwalked := secretTreeWalkOf(reflect.ValueOf(tree).Elem())
	if len(unwalked) != 0 {
		t.Fatalf("this walk could not read %v, so what it reports as retained is smaller than the type; widen it, or say in its comment why that kind cannot carry a secret",
			unwalked)
	}
	if len(held) == 0 {
		t.Fatal("the walk read no bytes at all out of a secret tree, so every gate scoped by it would be green over a tree that retained everything")
	}
	return held
}

// secretTreeWalkControlLeaf is a struct behind a pointer, which is the shape a secret takes
// when it is held in a map of pointers -- p4 task 22's ratchets, one commit from now.
type secretTreeWalkControlLeaf struct {
	secret []byte
}

// secretTreeWalkControl hides one distinct needle in every container the walk claims to read,
// so that what the walk can SEE is measured rather than assumed.
//
// A walk that returned nothing reports exactly what a walk over a tree that retained nothing
// reports, which is the one outcome a gate like this must never reach by accident. Every field
// here is unexported, because the fields of SecretTree are and reflect refuses Bytes and
// Interface on values reached through them; a control written with exported fields would
// exercise a path the real walk never takes.
type secretTreeWalkControl struct {
	plain            []byte
	nested           struct{ inner []byte }
	fixed            [4]byte
	behindAPointer   *secretTreeWalkControlLeaf
	inAMap           map[NodeIndex][]byte
	inAMapOfPointers map[string]*secretTreeWalkControlLeaf
	asAMapKey        map[string]bool
	inASliceOfSlices [][]byte
	asText           string
	asWideIntegers   []uint32
	behindAnAny      any
	aScalar          int
	absent           []byte
	andAMutex        sync.Mutex
}

// TestSecretTreeRetainedByteWalkReadsEveryContainerItClaimsTo is the control on the walk every
// forward secrecy claim in this file is scoped by.
//
// The needles are distinct per container, so a walk that found one of them and reported it
// eleven times satisfies nothing here, and one needle is planted NOWHERE and required to be
// absent, so a walk that answered every query yes fails too.
func TestSecretTreeRetainedByteWalkReadsEveryContainerItClaimsTo(t *testing.T) {
	needle := func(tag byte) []byte { return bytes.Repeat([]byte{tag}, 32) }
	wide := []uint32{}
	for range 8 {
		wide = append(wide, 0x0b0b0b0b)
	}
	control := &secretTreeWalkControl{
		plain:            needle(0x01),
		fixed:            [4]byte{0x03, 0x03, 0x03, 0x03},
		behindAPointer:   &secretTreeWalkControlLeaf{secret: needle(0x04)},
		inAMap:           map[NodeIndex][]byte{7: needle(0x05)},
		inAMapOfPointers: map[string]*secretTreeWalkControlLeaf{"r": {secret: needle(0x06)}},
		asAMapKey:        map[string]bool{string(needle(0x07)): true},
		inASliceOfSlices: [][]byte{needle(0x08)},
		asText:           string(needle(0x09)),
		asWideIntegers:   wide,
		behindAnAny:      needle(0x0c),
		aScalar:          42,
	}
	control.nested.inner = needle(0x02)

	held, unwalked := secretTreeWalkOf(reflect.ValueOf(control).Elem())
	if len(unwalked) != 0 {
		t.Fatalf("the walk declined %v of a fixture built entirely out of the kinds it claims to handle", unwalked)
	}
	for _, want := range []struct {
		what    string
		carried []byte
	}{
		{what: "a plain byte slice", carried: needle(0x01)},
		{what: "a byte slice inside a nested struct", carried: needle(0x02)},
		{what: "a byte array", carried: []byte{0x03, 0x03, 0x03, 0x03}},
		{what: "a byte slice behind a pointer to a struct", carried: needle(0x04)},
		{what: "a value of a map of byte slices", carried: needle(0x05)},
		{what: "a byte slice behind a map of pointers to structs", carried: needle(0x06)},
		{what: "the key of a map keyed by the secret itself", carried: needle(0x07)},
		{what: "a byte slice inside a slice of byte slices", carried: needle(0x08)},
		{what: "a string", carried: needle(0x09)},
		{what: "a run of wider integers", carried: needle(0x0b)},
		{what: "a byte slice behind an interface", carried: needle(0x0c)},
	} {
		found := ""
		for _, one := range held {
			if bytes.Contains(one.carried, want.carried) {
				found = one.where
				break
			}
		}
		if found == "" {
			t.Errorf("the walk did not read %s, so a SecretTree holding a destroyed secret there would pass every gate scoped by it", want.what)
		}
	}
	// and the walk is not answering yes to everything: this needle is planted nowhere.
	for _, one := range held {
		if bytes.Contains(one.carried, needle(0xff)) {
			t.Fatalf("the walk reported a needle nothing planted, at %s, so it is matching rather than reading", one.where)
		}
	}
	// the order is the walk's own and must not depend on go's map iteration: two walks of one
	// value that disagreed would make every count derived from a walk flap.
	second, _ := secretTreeWalkOf(reflect.ValueOf(control).Elem())
	if len(second) != len(held) {
		t.Fatalf("two walks of one value read %d values and %d", len(held), len(second))
	}
	for at := range held {
		if held[at].where != second[at].where || !bytes.Equal(held[at].carried, second[at].carried) {
			t.Fatalf("two walks of one value disagree at position %d: %s and %s", at, held[at].where, second[at].where)
		}
	}
}

// TestNewSecretTreeRejectsBadInput asserts a wrong-length root secret, a zero leaf count and
// a leaf count that is not a power of two are refused, so a tree can never exist in a shape
// no leaf can be reached in.
//
// The non-full count is the one that is only refused because Root's error is handled rather
// than shimmed away (convention C3): a shim answering node zero for it would build a tree
// with a leaf for a root.
func TestNewSecretTreeRejectsBadInput(t *testing.T) {
	crypto := stTestCrypto(t)
	good := MustHex(t, stVectorEncryptionSecret)
	if _, err := NewSecretTree(crypto, 8, good[:31]); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("short encryption secret err = %v, want ErrSecretLength", err)
	}
	if _, err := NewSecretTree(crypto, 8, append(append([]byte(nil), good...), 0x00)); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("long encryption secret err = %v, want ErrSecretLength", err)
	}
	if _, err := NewSecretTree(crypto, 8, nil); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("nil encryption secret err = %v, want ErrSecretLength", err)
	}
	if _, err := NewSecretTree(crypto, 0, good); !errors.Is(err, ErrSecretTreeLeafOutOfRange) {
		t.Fatalf("zero leaf count err = %v, want ErrSecretTreeLeafOutOfRange", err)
	}
	// every non-power-of-two count below the sweep's ceiling, derived rather than listed.
	refused := 0
	for n := LeafCount(1); n <= 64; n++ {
		if IsFullLeafCount(n) {
			continue
		}
		_, err := NewSecretTree(crypto, n, good)
		if !errors.Is(err, ErrSecretTreeLeafOutOfRange) {
			t.Fatalf("leaf count %d err = %v, want ErrSecretTreeLeafOutOfRange", n, err)
		}
		// p3's own sentinel survives the wrap, so a caller can ask which of the two range
		// failures this was rather than only that it was one of them.
		if !errors.Is(err, ErrLeafCountNotFull) {
			t.Fatalf("leaf count %d err = %v, want it to wrap ErrLeafCountNotFull too", n, err)
		}
		refused++
	}
	// 64 counts in 1..64, of which 1, 2, 4, 8, 16, 32 and 64 are full.
	if refused != 57 {
		t.Fatalf("refused %d non-full counts in 1..64, want 57", refused)
	}
	// the nil provider, at a sentinel of its own. It answered ErrSecretLength once, and this
	// test locked that in: a caller branching on a length failure re-derives and re-passes
	// its encryption_secret, which is the wrong repair for an argument it never supplied.
	if _, err := NewSecretTree(nil, 8, good); !errors.Is(err, ErrNilCryptoProvider) {
		t.Fatalf("nil provider err = %v, want ErrNilCryptoProvider rather than a nil dereference", err)
	}
	if _, err := NewSecretTree(nil, 8, good); errors.Is(err, ErrSecretLength) {
		t.Fatalf("nil provider err = %v, which still answers to ErrSecretLength; the two conditions "+
			"call for different repairs and a caller cannot tell them apart", err)
	}
}

// TestSecretTreeLeafCount asserts the accessor reports what was built, at the count type
// tree math defines. A LeafIndex here would compile and be wrong.
func TestSecretTreeLeafCount(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	for _, n := range stSweptLeafCounts() {
		tree, err := NewSecretTree(crypto, n, encryptionSecret)
		if err != nil {
			t.Fatalf("NewSecretTree(%d): %v", n, err)
		}
		var got LeafCount = tree.LeafCount()
		if got != n {
			t.Fatalf("LeafCount = %d, want %d", got, n)
		}
	}
}

// TestSecretTreeSingleLeafRootIsTheLeaf asserts that in a one-leaf tree the root node and
// leaf 0 are the same node, so the encryption secret is the leaf secret with no intervening
// "tree"/"left" derivation.
func TestSecretTreeSingleLeafRootIsTheLeaf(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	tree, err := NewSecretTree(crypto, 1, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	leafSecret, err := tree.takeLeafSecret(0)
	if err != nil {
		t.Fatalf("takeLeafSecret: %v", err)
	}
	if !bytes.Equal(leafSecret, encryptionSecret) {
		t.Fatalf("leaf secret = %x, want the encryption secret %x", leafSecret, encryptionSecret)
	}
}

// TestSecretTreeDescentDerivesBothChildren asserts a descent toward leaf 0 in an eight-leaf
// tree produces exactly the RFC's "tree"/"left" and "tree"/"right" expansions, and that
// leaf 7 is still reachable afterwards — and holds the right value — because the sibling
// subtree secret was retained and was derived before its parent was erased.
func TestSecretTreeDescentDerivesBothChildren(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	tree, err := NewSecretTree(crypto, 8, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}

	nh := crypto.HashSize()
	left := crypto.ExpandWithLabel(encryptionSecret, "tree", []byte("left"), nh)
	leftLeft := crypto.ExpandWithLabel(left, "tree", []byte("left"), nh)
	wantLeaf0 := crypto.ExpandWithLabel(leftLeft, "tree", []byte("left"), nh)

	got, err := tree.takeLeafSecret(0)
	if err != nil {
		t.Fatalf("takeLeafSecret(0): %v", err)
	}
	if !bytes.Equal(got, wantLeaf0) {
		t.Fatalf("leaf 0 secret = %x, want %x", got, wantLeaf0)
	}

	// the plan's version of this test asked only that leaf 7 still answered. That passes
	// against a descent that erased the root between its two children, because the right
	// subtree would then be a consistent tree derived from zeros. What separates them is the
	// value, so the value is what is compared.
	rightRight := crypto.ExpandWithLabel(
		crypto.ExpandWithLabel(encryptionSecret, "tree", []byte("right"), nh),
		"tree", []byte("right"), nh)
	wantLeaf7 := crypto.ExpandWithLabel(rightRight, "tree", []byte("right"), nh)
	leaf7, err := tree.takeLeafSecret(7)
	if err != nil {
		t.Fatalf("leaf 7 became unreachable after descending to leaf 0: %v", err)
	}
	if !bytes.Equal(leaf7, wantLeaf7) {
		t.Fatalf("leaf 7 secret = %x, want %x", leaf7, wantLeaf7)
	}
}

// TestSecretTreeDescentReachesEveryLeafOfEveryWidth is the descent's real coverage: every
// leaf of every full tree from one to sixty-four leaves, with the leaf set taken from the
// node array's width rather than chosen, and every answer compared against an independent
// replay of the ancestry p3's DirectPath reports.
//
// The pairwise distinctness at the end is what catches a descent that reaches A leaf rather
// than THE leaf: two leaves answering the same bytes is the shape a swapped Left/Right or a
// mis-signed comparison takes when the expectation happens to be symmetric.
func TestSecretTreeDescentReachesEveryLeafOfEveryWidth(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	compared := 0
	for _, n := range stSweptLeafCounts() {
		seen := map[string]LeafIndex{}
		for _, leaf := range stLeavesOf(t, n) {
			// a fresh tree per leaf, so this measures the descent and not the order the
			// previous leaves happened to consume the path in. The order is measured
			// separately below.
			tree, err := NewSecretTree(crypto, n, encryptionSecret)
			if err != nil {
				t.Fatalf("NewSecretTree(%d): %v", n, err)
			}
			got, err := tree.takeLeafSecret(leaf)
			if err != nil {
				t.Fatalf("takeLeafSecret(%d) in a %d leaf tree: %v", leaf, n, err)
			}
			want := stExpectedNodeSecret(t, crypto, encryptionSecret, n, leaf.NodeIndex())
			if !bytes.Equal(got, want) {
				t.Fatalf("leaf %d of %d = %x, want %x", leaf, n, got, want)
			}
			if other, ok := seen[string(got)]; ok {
				t.Fatalf("leaves %d and %d of a %d leaf tree have the same secret", other, leaf, n)
			}
			seen[string(got)] = leaf
			compared++
		}
	}
	// one comparison per leaf of each swept width: 1+2+4+8+16+32+64.
	if compared != 127 {
		t.Fatalf("compared %d leaves, want 127", compared)
	}
}

// stTakeOrders is every order this file consumes a tree's leaves in: forward, reverse, and
// outside in, which interleaves the two halves and so alternates which subtree consecutive
// takes descend into.
//
// One helper rather than one loop per test, so a test written later cannot silently cover
// fewer orders than the one beside it. Each order is checked to be a permutation of the leaf
// set rather than assumed to be one: an order that named a leaf twice would consume one leaf
// and report a sweep of the tree.
func stTakeOrders(t *testing.T, leaves []LeafIndex) [][]LeafIndex {
	t.Helper()
	forward := append([]LeafIndex(nil), leaves...)
	reverse := []LeafIndex{}
	for i := len(leaves) - 1; i >= 0; i-- {
		reverse = append(reverse, leaves[i])
	}
	interleaved := []LeafIndex{}
	for i, j := 0, len(leaves)-1; i <= j; i, j = i+1, j-1 {
		interleaved = append(interleaved, leaves[i])
		if i != j {
			interleaved = append(interleaved, leaves[j])
		}
	}
	orders := [][]LeafIndex{forward, reverse, interleaved}
	for _, order := range orders {
		if len(order) != len(leaves) {
			t.Fatalf("an order over %d leaves has %d entries", len(leaves), len(order))
		}
		seen := map[LeafIndex]bool{}
		for _, leaf := range order {
			if seen[leaf] {
				t.Fatalf("an order names leaf %d twice, so it consumes one leaf and reports a sweep of the tree", leaf)
			}
			seen[leaf] = true
		}
	}
	return orders
}

// TestSecretTreeEveryLeafSurvivesEveryTakeOrder asserts that consuming the leaves of one
// tree in any order gives every leaf the same secret a fresh tree gives it.
//
// This is the assertion the deletion has to survive. An erasure one step too early, or a
// parent erased before its second child is written, leaves the tree internally consistent —
// the remaining subtree still derives cleanly from whatever it was seeded with — so the only
// thing that sees it is a comparison against a derivation that never deleted anything.
func TestSecretTreeEveryLeafSurvivesEveryTakeOrder(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	compared := 0
	for _, n := range stSweptLeafCounts() {
		leaves := stLeavesOf(t, n)
		for _, order := range stTakeOrders(t, leaves) {
			tree, err := NewSecretTree(crypto, n, encryptionSecret)
			if err != nil {
				t.Fatalf("NewSecretTree(%d): %v", n, err)
			}
			for _, leaf := range order {
				got, err := tree.takeLeafSecret(leaf)
				if err != nil {
					t.Fatalf("takeLeafSecret(%d) of %d: %v", leaf, n, err)
				}
				want := stExpectedNodeSecret(t, crypto, encryptionSecret, n, leaf.NodeIndex())
				if !bytes.Equal(got, want) {
					t.Fatalf("leaf %d of %d taken in this order = %x, want %x", leaf, n, got, want)
				}
				compared++
			}
			// the tree is empty once every leaf has been taken: nothing was retained that
			// no leaf will ever ask for again.
			if len(tree.nodes) != 0 {
				t.Fatalf("a %d leaf tree retained %d node secrets after every leaf was taken", n, len(tree.nodes))
			}
		}
	}
	if compared != 3*127 {
		t.Fatalf("compared %d takes, want %d", compared, 3*127)
	}
}

// TestSecretTreeParentSecretIsGoneOnceBothChildrenExist is the deletion, observed rather
// than assumed.
//
// What "gone" can honestly mean in go, stated because the name of this test promises more
// than the language delivers. The assertion below reads the SAME backing array the tree
// handed to zeroizeSecret, so what it observes is that the bytes at that address are zero
// and that the map no longer names them. It cannot observe a copy the runtime made — a
// growth that moved the array, a spill to a stack frame that is now garbage, a value still
// in a register — and no go program can. secret_zeroize.go says the same thing at length and
// this test claims exactly what that file claims and nothing more.
//
// The other half of the claim is that both children existed BEFORE the parent went, and that
// is what the two value comparisons hold: the retained right subtree and the left subtree's
// surviving leaf both equal a derivation from the live root secret, which they could not if
// the root had been zeroized between the two stores.
func TestSecretTreeParentSecretIsGoneOnceBothChildrenExist(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	const leafCount = LeafCount(8)
	tree, err := NewSecretTree(crypto, leafCount, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	held, ok := tree.nodes[tree.root]
	if !ok {
		t.Fatalf("the constructor did not seed the root")
	}
	if len(held) != crypto.HashSize() {
		t.Fatalf("the root secret is %d bytes, want %d", len(held), crypto.HashSize())
	}
	// the control. Without it "held is all zeros" is satisfied by a tree that never held
	// anything, and the assertion would be measuring nothing.
	if bytes.Equal(held, make([]byte, len(held))) {
		t.Fatalf("the root secret was already zero before the descent, so this test measures nothing")
	}
	// what the root secret WAS, kept for the sweep at the end. held is about to be erased in
	// place, so a comparison against it afterwards would be a comparison against zeroes.
	rootSecret := append([]byte(nil), held...)

	if _, err := tree.takeLeafSecret(0); err != nil {
		t.Fatalf("takeLeafSecret(0): %v", err)
	}

	if _, ok := tree.nodes[tree.root]; ok {
		t.Fatalf("the root secret is still held after both of its children were derived")
	}
	if !bytes.Equal(held, make([]byte, len(held))) {
		t.Fatalf("the root's bytes are %x, want them erased in place", held)
	}
	// and gone from the TYPE, not only from the map and the one backing array this test
	// happened to keep a handle on. The handle says the bytes at that address were erased; it
	// says nothing about a copy the tree took before erasing them, which is one field away and
	// which every correctness test in this file agrees with. Measured: a tree that archived
	// each parent one line before zeroizing it passed all 750 tests of this package.
	for _, one := range secretTreeRetainedBytes(t, tree) {
		if bytes.Contains(one.carried, rootSecret) {
			t.Fatalf("the root secret is still held at %s after both of its children were derived", one.where)
		}
	}

	right, err := Right(tree.root)
	if err != nil {
		t.Fatalf("Right(root): %v", err)
	}
	retained, ok := tree.nodes[right]
	if !ok {
		t.Fatalf("the root's right child was not retained, so the erasure took the subtree with it")
	}
	if want := stExpectedNodeSecret(t, crypto, encryptionSecret, leafCount, right); !bytes.Equal(retained, want) {
		t.Fatalf("the retained right child = %x, want %x — it was not derived from the live root secret", retained, want)
	}
	// the left child is on the path and was itself expanded and erased, so what stands for
	// it is a leaf underneath it.
	leaf1, err := tree.takeLeafSecret(1)
	if err != nil {
		t.Fatalf("takeLeafSecret(1): %v", err)
	}
	if want := stExpectedNodeSecret(t, crypto, encryptionSecret, leafCount, LeafIndex(1).NodeIndex()); !bytes.Equal(leaf1, want) {
		t.Fatalf("leaf 1 = %x, want %x", leaf1, want)
	}
}

// TestSecretTreeDeletedSecretsAreNotDerivableFromWhatRemains is the property the deletion
// exists for: after a leaf has been taken, no sequence of derivations over the secrets the
// tree still holds reaches any secret it destroyed.
//
// The closure is computed rather than sampled. Derivation in section 9 goes one way — a node
// secret expands into its two children and nothing expands into a parent — so the full set an
// attacker holding the tree's remaining state can compute is exactly the subtrees under the
// retained nodes, and that set is walked in full and compared against every destroyed value.
func TestSecretTreeDeletedSecretsAreNotDerivableFromWhatRemains(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	const leafCount = LeafCount(8)
	tree, err := NewSecretTree(crypto, leafCount, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	taken, err := tree.takeLeafSecret(0)
	if err != nil {
		t.Fatalf("takeLeafSecret(0): %v", err)
	}

	// everything the take was supposed to destroy: leaf 0's own node and every ancestor of
	// it, named by tree math rather than by hand.
	target := LeafIndex(0).NodeIndex()
	ancestors, err := DirectPath(target, leafCount)
	if err != nil {
		t.Fatalf("DirectPath: %v", err)
	}
	destroyed := map[string]NodeIndex{}
	for _, node := range append([]NodeIndex{target}, ancestors...) {
		destroyed[string(stExpectedNodeSecret(t, crypto, encryptionSecret, leafCount, node))] = node
	}
	if len(destroyed) != len(ancestors)+1 {
		t.Fatalf("two of the destroyed nodes have the same secret, so this test cannot tell them apart")
	}
	// the taken leaf's own secret is one of them, which is what says the map holds the real
	// values and not a parallel mistake.
	if _, ok := destroyed[string(taken)]; !ok {
		t.Fatalf("the secret takeLeafSecret returned is not the one this test derived for leaf 0")
	}

	// what remains, derived from the TYPE and not from the name of a field. The version of
	// this test that walked `for node := range tree.nodes` passed against a tree that kept an
	// un-zeroized copy of every destroyed secret in a second field; secretTreeRetainedBytes
	// carries the measurement.
	held := secretTreeRetainedBytes(t, tree)
	nh := crypto.HashSize()

	// first, the trivial half the field-scoped version could not ask: nothing the tree still
	// reaches CONTAINS a destroyed secret. Containment and not equality, because a buffer
	// that concatenated several of them would hold every one.
	for _, one := range held {
		for secret, node := range destroyed {
			if bytes.Contains(one.carried, []byte(secret)) {
				t.Fatalf("node %d's secret is still held, at %s", node, one.where)
			}
		}
	}
	// the control on that sweep: the walk reaches the node map. Without it the loop above is
	// satisfied by a walk that read nothing at all.
	for node, secret := range tree.nodes {
		found := false
		for _, one := range held {
			if bytes.Equal(one.carried, secret) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("the walk did not report node %d's retained secret, so what it calls the retained state is not this tree's", node)
		}
	}

	// and then the closure over it. Derivation in section 9 goes one way -- a node secret
	// expands into its two children and nothing expands into a parent -- so expanding every
	// retained buffer with both labels, to the tree's own depth, is the whole of what an
	// attacker holding this state can compute.
	//
	// The seeds are the retained buffers whose length is the PROVIDER's hash size, which is
	// the only length a node secret has and the only length this provider expands from. A
	// retained buffer of any other length is judged by the containment sweep above and not by
	// this closure, which is a real limit of the closure and is why both halves are here.
	reachable := map[string]string{}
	frontier := []secretTreeHeld{}
	for _, one := range held {
		if len(one.carried) != nh {
			continue
		}
		reachable[string(one.carried)] = one.where
		frontier = append(frontier, one)
	}
	if len(frontier) == 0 {
		t.Fatal("no retained buffer is the provider's hash length, so this closure was seeded with nothing")
	}
	for range tree.depth {
		next := []secretTreeHeld{}
		for _, from := range frontier {
			for _, label := range []string{"left", "right"} {
				child := secretTreeHeld{
					where:   from.where + "/" + label,
					carried: crypto.ExpandWithLabel(from.carried, "tree", []byte(label), nh),
				}
				reachable[string(child.carried)] = child.where
				next = append(next, child)
			}
		}
		frontier = next
	}

	// the control on the closure, named by tree math rather than counted: node x roots the
	// subtree SubtreeSpan delimits, and every secret in it must be in the closure. A closure
	// that expanded nothing would otherwise satisfy the comparison below by being empty,
	// which is the one outcome this test must be unable to reach.
	legitimate := map[string]NodeIndex{}
	for node := range tree.nodes {
		first, last := SubtreeSpan(node)
		for at := first; at <= last; at++ {
			legitimate[string(stExpectedNodeSecret(t, crypto, encryptionSecret, leafCount, at))] = at
		}
	}
	// 11 for an eight leaf tree with leaf 0 taken: leaf 1, the level-1 node over leaves 2
	// and 3 with its two children, and the level-2 node over leaves 4 to 7 with its six.
	if len(legitimate) != 11 {
		t.Fatalf("the retained state roots %d derivable secrets, want 11", len(legitimate))
	}
	for secret, node := range legitimate {
		if _, ok := reachable[secret]; !ok {
			t.Fatalf("node %d lies under a node the tree retained and the closure did not reach it, so the closure is not walking", node)
		}
	}
	for secret, node := range destroyed {
		if where, ok := reachable[secret]; ok {
			t.Fatalf("node %d's secret is derivable from what the tree retained, as %s", node, where)
		}
	}
}

// TestSecretTreeLeafSecretIsTakenOnce asserts the second call for one leaf fails, in every
// swept width and for every leaf of it.
//
// Retaining it would keep a secret alive that has already produced both ratchet roots, which
// is exactly the forward secrecy RFC 9420 section 9 is for. The sweep is what stops this
// holding only for the first leaf of the first tree: an implementation that deleted the leaf
// but kept an ancestor would answer the second call from the ancestor, and only a leaf whose
// ancestors are still held shows it.
func TestSecretTreeLeafSecretIsTakenOnce(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	refused := 0
	for _, n := range stSweptLeafCounts() {
		for _, leaf := range stLeavesOf(t, n) {
			tree, err := NewSecretTree(crypto, n, encryptionSecret)
			if err != nil {
				t.Fatalf("NewSecretTree(%d): %v", n, err)
			}
			if _, err := tree.takeLeafSecret(leaf); err != nil {
				t.Fatalf("takeLeafSecret(%d): %v", leaf, err)
			}
			if _, err := tree.takeLeafSecret(leaf); !errors.Is(err, ErrSecretTreeConsumed) {
				t.Fatalf("second take of leaf %d of %d err = %v, want ErrSecretTreeConsumed", leaf, n, err)
			}
			refused++
		}
	}
	if refused != 127 {
		t.Fatalf("refused %d second takes, want 127", refused)
	}
}

// TestSecretTreeRejectsOutOfRangeLeaf asserts a leaf beyond the tree is a typed error and not
// an index panic on a message from a peer.
//
// The last two are the ones a smaller test misses. LeafIndex.NodeIndex is total and wraps at
// 2^31, so leaf 2^31 sits at node 0 — indistinguishable from leaf 0 to anything that range
// checks the NODE and not the LEAF. A tree that accepted it would hand out leaf 0's secret to
// a sender claiming an index no tree can hold.
func TestSecretTreeRejectsOutOfRangeLeaf(t *testing.T) {
	crypto := stTestCrypto(t)
	tree, err := NewSecretTree(crypto, 8, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	for _, leaf := range []LeafIndex{8, 9, 1 << 20, 1 << 31, (1 << 31) + 4, 0xffffffff} {
		if _, err := tree.takeLeafSecret(leaf); !errors.Is(err, ErrSecretTreeLeafOutOfRange) {
			t.Fatalf("leaf %d err = %v, want ErrSecretTreeLeafOutOfRange", leaf, err)
		}
	}
	// and the refusals cost nothing: leaf 0 is still there afterwards, so an out of range
	// index from a peer cannot be used to consume a leaf it does not own.
	if _, err := tree.takeLeafSecret(0); err != nil {
		t.Fatalf("leaf 0 after six refused indices: %v", err)
	}
}

// TestSecretTreeReadsItsSecretWidthOffTheProviderItWasHanded is the differential the registry
// cannot supply.
//
// Both registered suites fix Nh at 32, and 32 is also Nk on the chacha suite, the length of
// every vector in this tree, and the literal a body would have written down — so inside the
// registry a read of HashSize() and a written 32 are the same number and no test here can
// separate them. This provider is assembled instead, at the Nh 48 five registered suites
// carry, and every other length it reports differs from 48, so each substitution is a
// different number rather than the same one.
func TestSecretTreeReadsItsSecretWidthOffTheProviderItWasHanded(t *testing.T) {
	crypto := &suiteCryptoProvider{params: &labelKatSyntheticParams, random: rand.Reader}
	nh := crypto.HashSize()
	if nh != labelKatSyntheticParams.Nh {
		t.Fatalf("the fixture reports Nh %d, want %d", nh, labelKatSyntheticParams.Nh)
	}
	// the substitutions this provider has to be able to see. A length here equal to Nh would
	// leave every assertion below satisfied by the literal it exists to catch.
	for _, other := range []struct {
		name  string
		value int
	}{
		{name: "the registry's own hash size", value: 32},
		{name: "this suite's Nk", value: crypto.KeySize()},
		{name: "this suite's Nn", value: crypto.NonceSize()},
		{name: "this suite's Nt", value: labelKatSyntheticParams.Nt},
	} {
		if other.value == nh {
			t.Fatalf("%s is %d, the same as this fixture's Nh, so this differential is blind to it",
				other.name, other.value)
		}
	}

	encryptionSecret := bytes.Repeat([]byte{0x5a}, nh)
	// the length both registered suites fix is refused here, which is the length half of the
	// same claim: the constructor sizes its input by the provider and not by a literal.
	if _, err := NewSecretTree(crypto, 8, encryptionSecret[:32]); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("a 32 byte secret for an Nh 48 suite err = %v, want ErrSecretLength", err)
	}
	tree, err := NewSecretTree(crypto, 8, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	got, err := tree.takeLeafSecret(5)
	if err != nil {
		t.Fatalf("takeLeafSecret(5): %v", err)
	}
	if len(got) != nh {
		t.Fatalf("leaf secret is %d bytes for a suite whose Nh is %d", len(got), nh)
	}
	// and the length moved inside the preimage with it, not only in the size of the answer:
	// KDFLabel carries the length, so a body expanding to 32 and a body expanding to 48
	// disagree in every byte rather than in a prefix.
	want := stExpectedNodeSecret(t, crypto, encryptionSecret, 8, LeafIndex(5).NodeIndex())
	if !bytes.Equal(got, want) {
		t.Fatalf("leaf 5 = %x, want %x", got, want)
	}
	atThirtyTwo := crypto.ExpandWithLabel(encryptionSecret, "tree", []byte("right"), 32)
	atNh := crypto.ExpandWithLabel(encryptionSecret, "tree", []byte("right"), nh)
	if bytes.Equal(atThirtyTwo, atNh[:32]) {
		t.Fatalf("expanding to 32 and to %d agree on their first 32 bytes, so a hardcoded length "+
			"would be a truncation this test could not see", nh)
	}
	// worth recording, because it is why the assertion above is a prefix comparison and not
	// a whole tree derivation: with a hardcoded 32 the SECOND expansion of this suite is
	// handed a 32 byte pseudorandom key for a 48 byte hash, which the provider refuses
	// outright. So on this fixture a hardcoded width does not produce a wrong secret, it
	// produces no secret at all — a louder failure than the one being guarded against, but
	// only on a suite whose Nh exceeds 32, which is exactly what the registry does not have.

}

// TestSecretTreeDoesNotEraseTheCallersEncryptionSecret asserts the constructor copies what it
// is handed.
//
// The tree erases the secrets it holds, and the encryption secret it is seeded with is one of
// the nine the key schedule owns and zeroizes on its own schedule. Seeding the root with the
// caller's slice would mean building a secret tree silently destroyed the epoch's
// encryption_secret, and every existing test would still pass because the tree itself would
// be correct.
func TestSecretTreeDoesNotEraseTheCallersEncryptionSecret(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	original := append([]byte(nil), encryptionSecret...)
	tree, err := NewSecretTree(crypto, 4, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	if _, err := tree.takeLeafSecret(0); err != nil {
		t.Fatalf("takeLeafSecret: %v", err)
	}
	if !bytes.Equal(encryptionSecret, original) {
		t.Fatalf("the caller's encryption secret is now %x, want it untouched at %x", encryptionSecret, original)
	}
	// and the copy goes the other way too: mutating the caller's slice after construction
	// does not move the tree, so the tree is not aliasing it.
	fresh, err := NewSecretTree(crypto, 4, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	for i := range encryptionSecret {
		encryptionSecret[i] ^= 0xff
	}
	got, err := fresh.takeLeafSecret(2)
	if err != nil {
		t.Fatalf("takeLeafSecret: %v", err)
	}
	want := stExpectedNodeSecret(t, crypto, original, 4, LeafIndex(2).NodeIndex())
	if !bytes.Equal(got, want) {
		t.Fatalf("leaf 2 = %x, want %x — the tree aliased the caller's slice", got, want)
	}
}

// ---------------------------------------------------------------------------
// the properties the mutation round found nothing observing
// ---------------------------------------------------------------------------

// TestSecretTreeRetainsNoCopyOfADestroyedSecretInAnyFieldOfItsType is the "never delete"
// half of RFC 9420 section 9, over every leaf of every swept width.
//
// It is the property whose ABSENCE is invisible to every correctness test in this file. An
// implementation that keeps every node secret forever answers every "what is this leaf's
// secret" question identically to one that erases as it goes, so nothing that compares an
// answer separates them; the only thing that does is asking what the tree still holds
// afterwards, and asking it of the whole type rather than of one field.
//
// The scope is secretTreeRetainedBytes for exactly that reason. Measured: a SecretTree with an
// archive map[NodeIndex][]byte, written one line before each zeroizeSecret, keeps every
// ancestor of every consumed leaf for the epoch's lifetime and passed all 750 tests of this
// package before this test existed.
func TestSecretTreeRetainsNoCopyOfADestroyedSecretInAnyFieldOfItsType(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	checked := 0
	for _, n := range stSweptLeafCounts() {
		for _, leaf := range stLeavesOf(t, n) {
			tree, err := NewSecretTree(crypto, n, encryptionSecret)
			if err != nil {
				t.Fatalf("NewSecretTree(%d): %v", n, err)
			}
			taken, err := tree.takeLeafSecret(leaf)
			if err != nil {
				t.Fatalf("takeLeafSecret(%d) of %d: %v", leaf, n, err)
			}
			// everything that take was supposed to destroy: the leaf's own node and every
			// ancestor of it, named by tree math rather than by hand.
			target := leaf.NodeIndex()
			ancestors, err := DirectPath(target, n)
			if err != nil {
				t.Fatalf("DirectPath(%d, %d): %v", target, n, err)
			}
			destroyed := map[string]NodeIndex{}
			for _, node := range append([]NodeIndex{target}, ancestors...) {
				destroyed[string(stExpectedNodeSecret(t, crypto, encryptionSecret, n, node))] = node
			}
			if len(destroyed) != len(ancestors)+1 {
				t.Fatalf("two of the destroyed nodes of leaf %d of %d hold one secret, so this case cannot tell them apart", leaf, n)
			}
			// the taken secret is one of them, which is what says this map holds the real
			// values rather than a parallel mistake agreeing with itself.
			if _, ok := destroyed[string(taken)]; !ok {
				t.Fatalf("the secret takeLeafSecret returned for leaf %d of %d is not the one this test derived for it", leaf, n)
			}

			held := secretTreeRetainedBytes(t, tree)
			for _, one := range held {
				for secret, node := range destroyed {
					if bytes.Contains(one.carried, []byte(secret)) {
						t.Fatalf("node %d of a %d leaf tree was destroyed by taking leaf %d and its secret is still held at %s",
							node, n, leaf, one.where)
					}
				}
			}
			// the control on the walk, per tree: it reaches what the tree DID retain. Without
			// it the sweep above is satisfied by a walk that read nothing.
			for node, secret := range tree.nodes {
				found := false
				for _, one := range held {
					if bytes.Equal(one.carried, secret) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("the walk over a %d leaf tree did not report node %d's retained secret", n, node)
				}
			}
			checked += len(destroyed)
		}
	}
	// one destroyed node per ancestor plus the leaf, over every leaf of every swept width:
	// 1*1 + 2*2 + 4*3 + 8*4 + 16*5 + 32*6 + 64*7.
	if checked != 769 {
		t.Fatalf("checked %d destroyed node secrets, want 769", checked)
	}
}

// secretTreeGeometryFields is every field of SecretTree the constructor DERIVES from the leaf
// count, mapped to the tree math function that defines it.
//
// These four are cached once and read without the lock for the rest of the tree's life, and
// three of them are bounds: width bounds the node array, depth bounds the descent's runaway
// check, and root is where every descent starts. A cached bound that disagrees with the leaf
// count is invisible to every behavioural test, because the code it guards is unreachable for
// a well formed tree -- measured, on this file: width set to 0xffffffff and depth set to
// TreeDepth(n)+8 each left all 750 tests of this package passing. Comparing the cache against
// the function that defines it is what sees them.
var secretTreeGeometryFields = map[string]func(t *testing.T, n LeafCount) uint64{
	"leafCount": func(t *testing.T, n LeafCount) uint64 { return uint64(n) },
	"width":     func(t *testing.T, n LeafCount) uint64 { return uint64(NodeWidth(n)) },
	"depth":     func(t *testing.T, n LeafCount) uint64 { return uint64(TreeDepth(n)) },
	"root": func(t *testing.T, n LeafCount) uint64 {
		root, err := Root(n)
		if err != nil {
			t.Fatalf("Root(%d): %v", n, err)
		}
		return uint64(root)
	},
}

// secretTreeStateFields is the rest of SecretTree: the fields that are not a function of the
// leaf count, each with the reason it cannot be one.
//
// It exists so the check below can be COMPLETE over the type rather than over the four names
// somebody wrote down. A field added and left out of both maps fails, which is the point: p4
// task 22 adds ratchets to this struct, and the failure is where its author decides whether
// the new field is cached geometry or mutable state.
var secretTreeStateFields = map[string]string{
	"stateLock": "the mutex guarding the mutable fields; it holds no value to derive",
	"crypto":    "the provider the caller handed in, which the tree does not choose",
	"nodes":     "the mutable node secrets, whose contents change with every take",
	"ratchets":  "the per leaf hash ratchets, created on demand and advanced per message",
	"erased":    "whether Zeroize has run, which is a fact about this tree's lifetime and not about its shape",
}

// TestSecretTreeCachedGeometryIsDerivedFromTheLeafCount holds every cached bound of a
// constructed tree to the tree math function that defines it, at every swept width.
func TestSecretTreeCachedGeometryIsDerivedFromTheLeafCount(t *testing.T) {
	// the completeness half first, and it is the half with the consequence: a field of this
	// type judged by neither map is a cached value nothing compares.
	structure := reflect.TypeOf(SecretTree{})
	if structure.NumField() == 0 {
		t.Fatal("SecretTree has no fields, so this gate read the wrong type")
	}
	onTheType := map[string]bool{}
	for at := range structure.NumField() {
		name := structure.Field(at).Name
		onTheType[name] = true
		_, geometry := secretTreeGeometryFields[name]
		_, state := secretTreeStateFields[name]
		if geometry == state {
			t.Errorf("SecretTree.%s is judged by %s of the two maps; a field is either derived from the leaf count or it is not, and this gate cannot tell which",
				name, map[bool]string{true: "both", false: "neither"}[geometry])
		}
	}
	for _, name := range slices.Sorted(maps.Keys(secretTreeGeometryFields)) {
		if !onTheType[name] {
			t.Errorf("secretTreeGeometryFields names %s and SecretTree has no such field, so this sweep compares a field that is gone", name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(secretTreeStateFields)) {
		if !onTheType[name] {
			t.Errorf("secretTreeStateFields excuses %s and SecretTree has no such field; delete the entry", name)
		}
	}

	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	compared := 0
	for _, n := range stSweptLeafCounts() {
		tree, err := NewSecretTree(crypto, n, encryptionSecret)
		if err != nil {
			t.Fatalf("NewSecretTree(%d): %v", n, err)
		}
		value := reflect.ValueOf(tree).Elem()
		for _, name := range slices.Sorted(maps.Keys(secretTreeGeometryFields)) {
			field := value.FieldByName(name)
			if !field.IsValid() {
				t.Fatalf("SecretTree has no field %s", name)
			}
			if !field.CanUint() {
				t.Fatalf("SecretTree.%s is a %s and this sweep reads it as an unsigned integer; a retyped bound is a comparison this gate can no longer make",
					name, field.Kind())
			}
			if got, want := field.Uint(), secretTreeGeometryFields[name](t, n); got != want {
				t.Errorf("a %d leaf tree caches %s = %d, and tree math says %d", n, name, got, want)
			}
			compared++
		}
	}
	// four cached fields at each of the seven swept widths.
	if compared != 4*len(stSweptLeafCounts()) {
		t.Fatalf("compared %d cached values, want %d", compared, 4*len(stSweptLeafCounts()))
	}
}

// TestSecretTreePathToLeafLandsOnTheTargetOfEveryLeafOfEveryWidth asserts the descent's own
// invariants: it starts at the root, it steps to a child of the node it is standing on, it
// drops exactly one level per step, it is depth+1 nodes long, and it ENDS ON THE LEAF IT WAS
// AIMED AT.
//
// The last of those is why this test exists. secret_tree.go's post descent landing check is
// unreachable for a full tree -- replacing its condition with a constant false leaves every
// test in this package passing -- so no single edit can kill it, and the honest answer is to
// label it there and assert the invariant that makes it redundant here rather than leave the
// claim standing on an argument in a comment.
func TestSecretTreePathToLeafLandsOnTheTargetOfEveryLeafOfEveryWidth(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	walked := 0
	for _, n := range stSweptLeafCounts() {
		tree, err := NewSecretTree(crypto, n, encryptionSecret)
		if err != nil {
			t.Fatalf("NewSecretTree(%d): %v", n, err)
		}
		for _, leaf := range stLeavesOf(t, n) {
			path, err := tree.pathToLeaf(leaf)
			if err != nil {
				t.Fatalf("pathToLeaf(%d) of %d: %v", leaf, n, err)
			}
			if len(path) == 0 {
				t.Fatalf("the path to leaf %d of %d is empty", leaf, n)
			}
			if path[0] != tree.root {
				t.Fatalf("the path to leaf %d of %d starts at node %d, want the root %d", leaf, n, path[0], tree.root)
			}
			if path[len(path)-1] != leaf.NodeIndex() {
				t.Fatalf("the descent to leaf %d of %d ended at node %d, want node %d",
					leaf, n, path[len(path)-1], leaf.NodeIndex())
			}
			if uint32(len(path)) != tree.depth+1 {
				t.Fatalf("the path to leaf %d of %d is %d nodes long, want depth+1 = %d",
					leaf, n, len(path), tree.depth+1)
			}
			for at := 0; at+1 < len(path); at++ {
				left, err := Left(path[at])
				if err != nil {
					t.Fatalf("Left(%d): %v", path[at], err)
				}
				right, err := Right(path[at])
				if err != nil {
					t.Fatalf("Right(%d): %v", path[at], err)
				}
				if path[at+1] != left && path[at+1] != right {
					t.Fatalf("the path to leaf %d of %d steps from node %d to node %d, which is neither of its children %d and %d",
						leaf, n, path[at], path[at+1], left, right)
				}
				if path[at+1].Level()+1 != path[at].Level() {
					t.Fatalf("the path to leaf %d of %d steps from level %d to level %d",
						leaf, n, path[at].Level(), path[at+1].Level())
				}
			}
			walked++
		}
	}
	// one descent per leaf of each swept width: 1+2+4+8+16+32+64.
	if walked != 127 {
		t.Fatalf("walked %d descents, want 127", walked)
	}
}

// TestSecretTreeEveryParentOnEveryPathHasBothChildrenInsideTheNodeArray is the invariant
// behind the other labelled refusal in takeLeafSecret.
//
// The tree is always full -- section 7.7 makes a valid leaf count a power of two and Root
// refuses any other -- so both children of every parent the descent stands on are inside the
// node array and the child bound cannot fire. That used to be two ifs that SKIPPED a store
// when it did fire, which is the failure mode worth naming: a skipped store leaves every leaf
// under that child answering ErrSecretTreeConsumed, telling the caller forward secrecy did its
// job when what actually happened is that the tree dropped a subtree.
func TestSecretTreeEveryParentOnEveryPathHasBothChildrenInsideTheNodeArray(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	checked := 0
	for _, n := range stSweptLeafCounts() {
		tree, err := NewSecretTree(crypto, n, encryptionSecret)
		if err != nil {
			t.Fatalf("NewSecretTree(%d): %v", n, err)
		}
		for _, leaf := range stLeavesOf(t, n) {
			path, err := tree.pathToLeaf(leaf)
			if err != nil {
				t.Fatalf("pathToLeaf(%d) of %d: %v", leaf, n, err)
			}
			for at := 0; at+1 < len(path); at++ {
				left, err := Left(path[at])
				if err != nil {
					t.Fatalf("Left(%d): %v", path[at], err)
				}
				right, err := Right(path[at])
				if err != nil {
					t.Fatalf("Right(%d): %v", path[at], err)
				}
				if uint32(left) >= tree.width || uint32(right) >= tree.width {
					t.Fatalf("the children %d and %d of node %d lie outside a %d leaf tree's node array of width %d",
						left, right, path[at], n, tree.width)
				}
				checked++
			}
		}
	}
	// one parent per level per leaf: 2*1 + 4*2 + 8*3 + 16*4 + 32*5 + 64*6, and none in the
	// one leaf tree whose root is its leaf.
	if checked != 642 {
		t.Fatalf("checked %d parents, want 642", checked)
	}
}

// TestSecretTreeHeldNodesNeverShareARootLeafPath asserts the antichain invariant the deepest
// held ancestor scan rests on.
//
// Expanding a node deletes it and stores both of its children, so the nodes a tree still holds
// always form a frontier and no two of them sit on one root-leaf path. That is what makes
// "the deepest held node" and "the first held node" the same node, and it is why no single
// edit to that scan can be caught by the public surface -- taking the shallowest instead left
// all 750 tests of this package passing. The invariant had no assertion anywhere; it has one
// here, and the rule it makes redundant is measured on its own next door.
func TestSecretTreeHeldNodesNeverShareARootLeafPath(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	observed := 0
	for _, n := range stSweptLeafCounts() {
		leaves := stLeavesOf(t, n)
		for _, order := range stTakeOrders(t, leaves) {
			tree, err := NewSecretTree(crypto, n, encryptionSecret)
			if err != nil {
				t.Fatalf("NewSecretTree(%d): %v", n, err)
			}
			for _, taken := range order {
				if _, err := tree.takeLeafSecret(taken); err != nil {
					t.Fatalf("takeLeafSecret(%d) of %d: %v", taken, n, err)
				}
				for _, leaf := range leaves {
					path, err := tree.pathToLeaf(leaf)
					if err != nil {
						t.Fatalf("pathToLeaf(%d) of %d: %v", leaf, n, err)
					}
					onThePath := []NodeIndex{}
					for _, node := range path {
						if _, ok := tree.nodes[node]; ok {
							onThePath = append(onThePath, node)
						}
					}
					if len(onThePath) > 1 {
						t.Fatalf("after taking leaf %d of a %d leaf tree, nodes %v are all held and all sit on the path to leaf %d",
							taken, n, onThePath, leaf)
					}
					observed++
				}
			}
		}
	}
	// every leaf's path examined after every take, in three orders, at each swept width:
	// 3 * (1 + 4 + 16 + 64 + 256 + 1024 + 4096).
	if observed != 16383 {
		t.Fatalf("examined %d paths, want 16383", observed)
	}
}

// TestSecretTreeTakesTheDeepestHeldAncestorAndNotTheShallowest is the one state in which the
// two rules name different nodes, and it has to be planted because the antichain invariant
// next door says the tree never reaches it on its own.
//
// The planting is the point rather than a shortcut. takeLeafSecret's scan is written as "the
// deepest held node" and the reason it matters is what happens if the invariant ever broke:
// starting from a shallower ancestor re-derives and OVERWRITES the subtree below it from a
// secret the tree has already promised to destroy, so every leaf under that ancestor would
// then be a value an attacker holding the erased secret can compute. Nothing observed that,
// and taking the shallowest instead of the deepest left all 750 tests of this package passing.
func TestSecretTreeTakesTheDeepestHeldAncestorAndNotTheShallowest(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	const leafCount = LeafCount(8)
	nh := crypto.HashSize()
	tree, err := NewSecretTree(crypto, leafCount, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	if _, err := tree.takeLeafSecret(0); err != nil {
		t.Fatalf("takeLeafSecret(0): %v", err)
	}

	// leaf 2's path, and the one node of it the tree still holds. Both are read off the tree
	// rather than written down, so the fixture cannot drift away from the shape it needs.
	const target = LeafIndex(2)
	path, err := tree.pathToLeaf(target)
	if err != nil {
		t.Fatalf("pathToLeaf(%d): %v", target, err)
	}
	stillHeld := []int{}
	for at, node := range path {
		if _, ok := tree.nodes[node]; ok {
			stillHeld = append(stillHeld, at)
		}
	}
	if len(stillHeld) != 1 {
		t.Fatalf("%d nodes of the path to leaf %d are held; this fixture needs exactly one", len(stillHeld), target)
	}
	deeper := stillHeld[0]
	if deeper < 1 {
		t.Fatalf("the held node is at the root of the path, so there is no erased ancestor above it to plant at")
	}
	planted := path[deeper-1]
	if _, ok := tree.nodes[planted]; ok {
		t.Fatalf("node %d is still held, so planting there would not be planting a STALE ancestor", planted)
	}

	stale := bytes.Repeat([]byte{0xa5}, nh)
	tree.nodes[planted] = append([]byte(nil), stale...)

	// what the shallow rule would answer, replayed from the planted node down the same path.
	fromStale := append([]byte(nil), stale...)
	for at := deeper - 1; at+1 < len(path); at++ {
		left, err := Left(path[at])
		if err != nil {
			t.Fatalf("Left(%d): %v", path[at], err)
		}
		label := "right"
		if path[at+1] == left {
			label = "left"
		}
		fromStale = crypto.ExpandWithLabel(fromStale, "tree", []byte(label), nh)
	}
	want := stExpectedNodeSecret(t, crypto, encryptionSecret, leafCount, target.NodeIndex())
	// the control: the two rules answer different values here, so this test can tell them
	// apart. Without it a fixture where they agreed would pass either way.
	if bytes.Equal(fromStale, want) {
		t.Fatalf("the stale ancestor at node %d derives the same secret as the node still held, so this test cannot separate the two rules", planted)
	}

	got, err := tree.takeLeafSecret(target)
	if err != nil {
		t.Fatalf("takeLeafSecret(%d): %v", target, err)
	}
	if bytes.Equal(got, fromStale) {
		t.Fatalf("leaf %d was derived from the stale ancestor at node %d rather than from the deeper node still held; every leaf under node %d is now a value anyone holding the erased ancestor can compute",
			target, planted, planted)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("leaf %d = %x, want %x", target, got, want)
	}
}

// TestSecretTreeASecondTakeIsAlwaysTheConsumedRefusalAndNeverTheInvariantOne holds every
// legitimate refusal to the FIRST of takeLeafSecret's two ErrSecretTreeConsumed returns.
//
// The second one -- reached when the descent did not store the leaf it descended to -- is
// unreachable: the expansion loop stores both children of every node it expands and its last
// iteration expands the target's parent, and when the loop does not run the deepest held node
// was already the target. It was reclassified to an unrelated sentinel with every test in this
// package still passing, which is exactly what happens to an unreachable return that nothing
// names, so it now wraps a sentinel of its own and this test says which of the two fires.
func TestSecretTreeASecondTakeIsAlwaysTheConsumedRefusalAndNeverTheInvariantOne(t *testing.T) {
	// the control on the matcher. The two returns differ only in the sentinel the second
	// wraps, so an errors.Is that could not see it through the wrapping would report every
	// refusal as the ordinary one no matter which return produced it.
	both := fmt.Errorf("%w: leaf 0: %w", ErrSecretTreeConsumed, errSecretTreeDescentDidNotStoreTheTarget)
	if !errors.Is(both, ErrSecretTreeConsumed) || !errors.Is(both, errSecretTreeDescentDidNotStoreTheTarget) {
		t.Fatalf("the two sentinels are not both visible through %v, so this test cannot tell the two returns apart", both)
	}
	if errors.Is(fmt.Errorf("%w: leaf 0", ErrSecretTreeConsumed), errSecretTreeDescentDidNotStoreTheTarget) {
		t.Fatal("the ordinary consumed refusal answers to the invariant sentinel, so every refusal below would read as the invariant one")
	}

	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	refused := 0
	for _, n := range stSweptLeafCounts() {
		leaves := stLeavesOf(t, n)
		for _, order := range stTakeOrders(t, leaves) {
			tree, err := NewSecretTree(crypto, n, encryptionSecret)
			if err != nil {
				t.Fatalf("NewSecretTree(%d): %v", n, err)
			}
			for _, leaf := range order {
				if _, err := tree.takeLeafSecret(leaf); err != nil {
					t.Fatalf("takeLeafSecret(%d) of %d: %v", leaf, n, err)
				}
				_, err := tree.takeLeafSecret(leaf)
				if !errors.Is(err, ErrSecretTreeConsumed) {
					t.Fatalf("the second take of leaf %d of %d err = %v, want ErrSecretTreeConsumed", leaf, n, err)
				}
				if errors.Is(err, errSecretTreeDescentDidNotStoreTheTarget) {
					t.Fatalf("the second take of leaf %d of %d was refused by the post descent return, which is reachable only if the descent stopped storing the leaf it descended to: %v",
						leaf, n, err)
				}
				refused++
			}
		}
	}
	// every leaf of every swept width, taken again immediately, in three orders.
	if refused != 3*127 {
		t.Fatalf("refused %d second takes, want %d", refused, 3*127)
	}
}

// ---------------------------------------------------------------------------
// task 22 and 23: the plan's own tests, kept where they observe something
// ---------------------------------------------------------------------------

// TestRatchetRootsUseDistinctLabels asserts the handshake and application ratchets
// are separate expansions of the same leaf secret. Sharing one ratchet between
// handshake and application messages would reuse an AEAD key and nonce pair.
func TestRatchetRootsUseDistinctLabels(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	tree, err := NewSecretTree(crypto, 1, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	handshake, err := tree.ratchetFor(0, RatchetHandshake)
	if err != nil {
		t.Fatalf("ratchetFor handshake: %v", err)
	}
	application, err := tree.ratchetFor(0, RatchetApplication)
	if err != nil {
		t.Fatalf("ratchetFor application: %v", err)
	}
	nh := crypto.HashSize()
	wantHandshake := crypto.ExpandWithLabel(encryptionSecret, "handshake", nil, nh)
	wantApplication := crypto.ExpandWithLabel(encryptionSecret, "application", nil, nh)
	if !bytes.Equal(handshake.secret, wantHandshake) {
		t.Fatalf("handshake root = %x, want %x", handshake.secret, wantHandshake)
	}
	if !bytes.Equal(application.secret, wantApplication) {
		t.Fatalf("application root = %x, want %x", application.secret, wantApplication)
	}
}

// TestRatchetStepDerivesKeyNonceAndSuccessor pins the three DeriveTreeSecret calls of
// RFC 9420 section 9.1 and asserts the ratchet advances by exactly one generation.
func TestRatchetStepDerivesKeyNonceAndSuccessor(t *testing.T) {
	crypto := stTestCrypto(t)
	tree, err := NewSecretTree(crypto, 1, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	r, err := tree.ratchetFor(0, RatchetApplication)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	root := append([]byte(nil), r.secret...)
	wantKey := crypto.DeriveTreeSecret(root, "key", 0, crypto.KeySize())
	wantNonce := crypto.DeriveTreeSecret(root, "nonce", 0, crypto.NonceSize())
	wantNext := crypto.DeriveTreeSecret(root, "secret", 0, crypto.HashSize())

	generation, keys, err := r.step()
	if err != nil {
		t.Fatalf("step: %v", err)
	}
	if generation != 0 {
		t.Fatalf("generation = %d, want 0", generation)
	}
	if !bytes.Equal(keys.key, wantKey) {
		t.Fatalf("key = %x, want %x", keys.key, wantKey)
	}
	if !bytes.Equal(keys.nonce, wantNonce) {
		t.Fatalf("nonce = %x, want %x", keys.nonce, wantNonce)
	}
	if !bytes.Equal(r.secret, wantNext) {
		t.Fatalf("successor secret = %x, want %x", r.secret, wantNext)
	}
	if r.head != 1 {
		t.Fatalf("head = %d, want 1", r.head)
	}
}

// TestRatchetStepBindsTheGeneration asserts generation 1 uses generation 1 in the
// DeriveTreeSecret context and not 0, so a copy-paste of the previous call is caught.
func TestRatchetStepBindsTheGeneration(t *testing.T) {
	crypto := stTestCrypto(t)
	tree, err := NewSecretTree(crypto, 1, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	r, err := tree.ratchetFor(0, RatchetApplication)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	if _, _, err := r.step(); err != nil {
		t.Fatalf("step: %v", err)
	}
	secondRoot := append([]byte(nil), r.secret...)
	wantKey := crypto.DeriveTreeSecret(secondRoot, "key", 1, crypto.KeySize())
	generation, keys, err := r.step()
	if err != nil {
		t.Fatalf("step: %v", err)
	}
	if generation != 1 {
		t.Fatalf("generation = %d, want 1", generation)
	}
	if !bytes.Equal(keys.key, wantKey) {
		t.Fatalf("generation 1 key is not bound to generation 1")
	}
}

// TestRatchetKeysAreNeverRepeated asserts the first two hundred generations produce
// two hundred distinct key and nonce pairs, which is the AEAD safety property.
//
// Two hundred consecutive generations from zero is the middle of the range and cannot see
// a boundary; TestRatchetKeyNonceAndSuccessorAreDerivedAtEveryGenerationBoundary and
// TestRatchetRefusesToWrapTheGenerationCounter are where the ends are.
func TestRatchetKeysAreNeverRepeated(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 1, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	r, err := tree.ratchetFor(0, RatchetApplication)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	seen := map[string]uint32{}
	for i := 0; i < 200; i++ {
		generation, keys, err := r.step()
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		fingerprint := string(keys.key) + "|" + string(keys.nonce)
		if previous, ok := seen[fingerprint]; ok {
			t.Fatalf("generation %d repeats the key and nonce of generation %d", generation, previous)
		}
		seen[fingerprint] = generation
	}
}

// TestNextSenderKeyAdvances asserts the sender path hands out consecutive generations
// and never repeats one.
//
// The two lengths are the plan's literals and are kept as literals on purpose: on this
// suite they are the right numbers, and what they cannot see -- a body that writes 32 and
// 12 down instead of reading them -- is measured on a suite whose Nk and Nn are neither,
// in TestRatchetReadsItsKeyAndNonceWidthsOffTheProviderItWasHanded.
func TestNextSenderKeyAdvances(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 8, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	for want := uint32(0); want < 5; want++ {
		generation, key, nonce, err := tree.NextSenderKey(2, RatchetApplication)
		if err != nil {
			t.Fatalf("NextSenderKey: %v", err)
		}
		if generation != want {
			t.Fatalf("generation = %d, want %d", generation, want)
		}
		if len(key) != 32 || len(nonce) != 12 {
			t.Fatalf("key %d bytes, nonce %d bytes", len(key), len(nonce))
		}
	}
	generation, err := tree.SenderGeneration(2, RatchetApplication)
	if err != nil {
		t.Fatalf("SenderGeneration: %v", err)
	}
	if generation != 5 {
		t.Fatalf("SenderGeneration = %d, want 5", generation)
	}
}

// TestReceiverKeyOutOfOrderUsesTheWindow asserts a message that arrives at generation
// 3 before generations 0 to 2 does not destroy them, which is what makes an out-of-
// order delivery a delay rather than three lost messages.
func TestReceiverKeyOutOfOrderUsesTheWindow(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)

	sender, err := NewSecretTree(crypto, 8, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	expected := map[uint32][]byte{}
	for i := 0; i < 4; i++ {
		generation, key, _, err := sender.NextSenderKey(5, RatchetHandshake)
		if err != nil {
			t.Fatalf("NextSenderKey: %v", err)
		}
		expected[generation] = key
	}

	receiver, err := NewSecretTree(crypto, 8, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	got3, _, err := receiver.ReceiverKey(5, RatchetHandshake, 3)
	if err != nil {
		t.Fatalf("ReceiverKey(3): %v", err)
	}
	if !bytes.Equal(got3, expected[3]) {
		t.Fatalf("generation 3 key mismatch")
	}
	for _, generation := range []uint32{0, 1, 2} {
		got, _, err := receiver.ReceiverKey(5, RatchetHandshake, generation)
		if err != nil {
			t.Fatalf("ReceiverKey(%d): %v", generation, err)
		}
		if !bytes.Equal(got, expected[generation]) {
			t.Fatalf("generation %d key mismatch", generation)
		}
	}
}

// TestReceiverKeyIsSingleUse asserts a generation cannot be fetched twice, so a
// replayed message cannot be decrypted a second time from the window.
//
// It is the one test in this file that observes a real key and nonce REPEAT rather than a
// derivation defect: everywhere else the generation number is bound into the KDF context,
// so a repeat needs two independent faults, while the window can hand one pair back twice
// with a single missing delete.
func TestReceiverKeyIsSingleUse(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 8, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	if _, _, err := tree.ReceiverKey(1, RatchetApplication, 0); err != nil {
		t.Fatalf("ReceiverKey: %v", err)
	}
	if _, _, err := tree.ReceiverKey(1, RatchetApplication, 0); !errors.Is(err, ErrRatchetGenerationConsumed) {
		t.Fatalf("err = %v, want ErrRatchetGenerationConsumed", err)
	}
	// and the same for a generation that came out of the WINDOW rather than off the head,
	// which is the path with the delete in it.
	if _, _, err := tree.ReceiverKey(1, RatchetApplication, 4); err != nil {
		t.Fatalf("ReceiverKey(4): %v", err)
	}
	if _, _, err := tree.ReceiverKey(1, RatchetApplication, 2); err != nil {
		t.Fatalf("ReceiverKey(2) out of the window: %v", err)
	}
	if _, _, err := tree.ReceiverKey(1, RatchetApplication, 2); !errors.Is(err, ErrRatchetGenerationConsumed) {
		t.Fatalf("a window generation was handed out twice: err = %v, want ErrRatchetGenerationConsumed", err)
	}
}

// TestReceiverKeyRefusesUnboundedSkip asserts a forged generation number cannot force
// an unbounded KDF loop. Without this bound a single 32-bit field is a denial of
// service that costs the sender nothing.
func TestReceiverKeyRefusesUnboundedSkip(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 8, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	_, _, err = tree.ReceiverKey(1, RatchetApplication, MaxGenerationSkip+1)
	if !errors.Is(err, ErrRatchetGenerationTooFarAhead) {
		t.Fatalf("err = %v, want ErrRatchetGenerationTooFarAhead", err)
	}
	if _, _, err := tree.ReceiverKey(1, RatchetApplication, ^uint32(0)); !errors.Is(err, ErrRatchetGenerationTooFarAhead) {
		t.Fatalf("err = %v, want ErrRatchetGenerationTooFarAhead", err)
	}
	// the ratchet must be untouched by a refused request
	generation, err := tree.SenderGeneration(1, RatchetApplication)
	if err != nil {
		t.Fatalf("SenderGeneration: %v", err)
	}
	if generation != 0 {
		t.Fatalf("a refused request advanced the ratchet to %d", generation)
	}
}

// TestSecretTreeZeroize asserts every retained node secret and ratchet secret is
// cleared when the epoch is dropped.
func TestSecretTreeZeroize(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 8, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	if _, _, _, err := tree.NextSenderKey(0, RatchetApplication); err != nil {
		t.Fatalf("NextSenderKey: %v", err)
	}
	r, err := tree.ratchetFor(0, RatchetApplication)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	retained := append([]byte(nil), r.secret...)
	tree.Zeroize()
	if bytes.Equal(r.secret, retained) {
		t.Fatal("the ratchet secret survived Zeroize")
	}
	for node, secret := range tree.nodes {
		for _, b := range secret {
			if b != 0 {
				t.Fatalf("node %d secret survived Zeroize", node)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// the ratchet properties a middle-of-the-range test cannot see
// ---------------------------------------------------------------------------

// stNewTree builds a tree of the given width over the vector encryption secret.
func stNewTree(t *testing.T, leafCount LeafCount) *SecretTree {
	t.Helper()
	tree, err := NewSecretTree(stTestCrypto(t), leafCount, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree(%d): %v", leafCount, err)
	}
	return tree
}

// stRatchetKinds is both ratchet types, derived from the iota run rather than listed, so a
// third type added to the constant block joins every sweep below instead of being covered
// by whichever of these two a sweep happened to name.
func stRatchetKinds() []RatchetType {
	kinds := []RatchetType{}
	for kind := RatchetHandshake; kind <= RatchetApplication; kind++ {
		kinds = append(kinds, kind)
	}
	return kinds
}

// stRatchetLabel is the RFC 9420 section 9 label each ratchet type expands its leaf secret
// under. It is a switch and not a map so a type added without a label fails the build here
// rather than expanding under the empty string.
func stRatchetLabel(t *testing.T, kind RatchetType) string {
	t.Helper()
	switch kind {
	case RatchetHandshake:
		return "handshake"
	case RatchetApplication:
		return "application"
	}
	t.Fatalf("ratchet type %d has no label in this test's own table, so nothing here derives its root", kind)
	return ""
}

// stRatchetRoot derives one leaf's ratchet root independently of the code under test: the
// node secret comes from stExpectedNodeSecret, which walks the tree math upward, and the
// expansion is the section 9 label.
func stRatchetRoot(t *testing.T, crypto CryptoProvider, encryptionSecret []byte,
	leafCount LeafCount, leaf LeafIndex, kind RatchetType) []byte {
	t.Helper()
	leafSecret := stExpectedNodeSecret(t, crypto, encryptionSecret, leafCount, leaf.NodeIndex())
	return crypto.ExpandWithLabel(leafSecret, stRatchetLabel(t, kind), nil, crypto.HashSize())
}

// stAllZero reports whether every byte is zero, which is what an erased secret looks like.
func stAllZero(b []byte) bool {
	for _, one := range b {
		if one != 0 {
			return false
		}
	}
	return true
}

// stGenerationBoundaries is the generations this file sweeps, DERIVED from the width of the
// counter rather than typed out.
//
// A nonce defect has already shipped on this project at 2^32 while sixty-nine tests that all
// sat in the middle of the range reported green, so what this covers is the edges: zero, one
// past it, both sides of every byte boundary the counter has, and the last two values it can
// hold. Every entry comes out of the loop, so a counter that was ever widened sweeps the new
// boundaries without anyone editing a list.
func stGenerationBoundaries() []uint32 {
	last := ^uint32(0)
	bits := 0
	for shifted := last; shifted != 0; shifted >>= 1 {
		bits++
	}
	out := []uint32{0, 1, 2}
	for at := 8; at < bits; at += 8 {
		edge := uint32(1) << at
		out = append(out, edge-1, edge, edge+1)
	}
	out = append(out, last-1, last)
	return out
}

// TestRatchetGenerationBoundarySweepReachesTheEndsOfTheCounter is the control on the sweep
// every boundary test below is scoped by. A generator that returned three small numbers
// would leave each of those tests reporting green over the middle of the range, which is
// exactly the shape of the defect this file is guarding against.
func TestRatchetGenerationBoundarySweepReachesTheEndsOfTheCounter(t *testing.T) {
	swept := stGenerationBoundaries()
	last := ^uint32(0)
	for _, want := range []uint32{0, 1, 1 << 8, 1<<16 - 1, 1 << 16, 1 << 24, last - 1, last} {
		if !slices.Contains(swept, want) {
			t.Errorf("the boundary sweep does not reach generation %d", want)
		}
	}
	if len(swept) != len(slices.Compact(slices.Sorted(slices.Values(swept)))) {
		t.Fatalf("the boundary sweep repeats a generation, so its counts are not what they look like")
	}
	// three at each of the three interior byte boundaries, plus zero, one, two, and the last
	// two values the counter holds.
	if len(swept) != 3+3*3+2 {
		t.Fatalf("the boundary sweep has %d entries, want %d", len(swept), 3+3*3+2)
	}
}

// TestRatchetKeyNonceAndSuccessorAreDerivedAtEveryGenerationBoundary asserts that at each
// end of the counter the three derivations are still the RFC 9420 section 9.1 ones and that
// no two generations reach the same key and nonce pair.
//
// The ratchet is PLANTED at each boundary rather than stepped to it. Reaching 2^32-1 one
// step at a time is four billion HKDF calls, and the generations that need covering are
// precisely the ones no loop a test can run ever arrives at -- which is why the shipped
// defect this guards against was invisible: everything anyone ran stopped in the middle.
func TestRatchetKeyNonceAndSuccessorAreDerivedAtEveryGenerationBoundary(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	const leafCount = LeafCount(8)
	const leaf = LeafIndex(3)
	root := stRatchetRoot(t, crypto, encryptionSecret, leafCount, leaf, RatchetApplication)

	pairs := map[string]uint32{}
	nonces := map[string]uint32{}
	keys := map[string]uint32{}
	for _, generation := range stGenerationBoundaries() {
		tree := stNewTree(t, leafCount)
		r, err := tree.ratchetFor(leaf, RatchetApplication)
		if err != nil {
			t.Fatalf("ratchetFor: %v", err)
		}
		// the control on the planting: the fixture below derives from the same root the
		// ratchet is actually holding, so a disagreement is the step and not the fixture.
		if !bytes.Equal(r.secret, root) {
			t.Fatalf("the ratchet root is %x and this test derived %x", r.secret, root)
		}
		r.head = generation

		stepped, got, err := r.step()
		if err != nil {
			t.Fatalf("step at generation %d: %v", generation, err)
		}
		if stepped != generation {
			t.Fatalf("a ratchet at generation %d produced generation %d", generation, stepped)
		}
		wantKey := crypto.DeriveTreeSecret(root, "key", generation, crypto.KeySize())
		wantNonce := crypto.DeriveTreeSecret(root, "nonce", generation, crypto.NonceSize())
		wantNext := crypto.DeriveTreeSecret(root, "secret", generation, crypto.HashSize())
		if !bytes.Equal(got.key, wantKey) {
			t.Fatalf("generation %d key = %x, want %x", generation, got.key, wantKey)
		}
		if !bytes.Equal(got.nonce, wantNonce) {
			t.Fatalf("generation %d nonce = %x, want %x", generation, got.nonce, wantNonce)
		}
		if !bytes.Equal(r.secret, wantNext) {
			t.Fatalf("generation %d successor = %x, want %x", generation, r.secret, wantNext)
		}
		if stAllZero(got.nonce) || stAllZero(got.key) {
			t.Fatalf("generation %d produced a zero key or nonce", generation)
		}

		if previous, ok := pairs[string(got.key)+"|"+string(got.nonce)]; ok {
			t.Fatalf("generation %d reaches the same key and nonce pair as generation %d, which is the AEAD break this sweep exists for",
				generation, previous)
		}
		pairs[string(got.key)+"|"+string(got.nonce)] = generation
		// the halves separately as well. A pair stays unique if only one half moves, so a
		// nonce frozen across generations is invisible to the pair check while being the
		// exact defect that matters if the key ever stops moving too.
		if previous, ok := nonces[string(got.nonce)]; ok {
			t.Fatalf("generation %d repeats the nonce of generation %d", generation, previous)
		}
		nonces[string(got.nonce)] = generation
		if previous, ok := keys[string(got.key)]; ok {
			t.Fatalf("generation %d repeats the key of generation %d", generation, previous)
		}
		keys[string(got.key)] = generation
	}
	if len(pairs) != len(stGenerationBoundaries()) {
		t.Fatalf("swept %d generations and collected %d pairs", len(stGenerationBoundaries()), len(pairs))
	}
}

// TestRatchetKeysAreNeverRepeatedOverAContiguousSweep is the same property over an unbroken
// run rather than over sampled boundaries, so a body that is right at every edge this file
// names and wrong three steps in has nowhere to hide.
func TestRatchetKeysAreNeverRepeatedOverAContiguousSweep(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	const leafCount = LeafCount(8)
	const leaf = LeafIndex(6)
	const generations = 4096

	tree := stNewTree(t, leafCount)
	r, err := tree.ratchetFor(leaf, RatchetHandshake)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	// the independent chain, walked forward from the root this test derived itself.
	secret := stRatchetRoot(t, crypto, encryptionSecret, leafCount, leaf, RatchetHandshake)
	pairs := map[string]uint32{}
	for want := uint32(0); want < generations; want++ {
		wantKey := crypto.DeriveTreeSecret(secret, "key", want, crypto.KeySize())
		wantNonce := crypto.DeriveTreeSecret(secret, "nonce", want, crypto.NonceSize())
		secret = crypto.DeriveTreeSecret(secret, "secret", want, crypto.HashSize())

		generation, got, err := r.step()
		if err != nil {
			t.Fatalf("step %d: %v", want, err)
		}
		if generation != want {
			t.Fatalf("step %d produced generation %d", want, generation)
		}
		if !bytes.Equal(got.key, wantKey) || !bytes.Equal(got.nonce, wantNonce) {
			t.Fatalf("generation %d disagrees with the independently derived chain", generation)
		}
		if previous, ok := pairs[string(got.key)+"|"+string(got.nonce)]; ok {
			t.Fatalf("generation %d repeats the key and nonce pair of generation %d", generation, previous)
		}
		pairs[string(got.key)+"|"+string(got.nonce)] = generation
	}
	if len(pairs) != generations {
		t.Fatalf("collected %d pairs over %d generations", len(pairs), generations)
	}
	if !bytes.Equal(r.secret, secret) {
		t.Fatalf("after %d generations the ratchet secret has drifted from the independent chain", generations)
	}
}

// TestRatchetRefusesToWrapTheGenerationCounter asserts the ratchet stops at 2^32-1 instead
// of rolling the counter back to zero.
//
// A wrap is not a lost message. It is the generation numbers on the wire starting again at
// zero under keys that have moved on, so every one of them collides with a number this
// receiver has already marked consumed, and the four billionth message silently becomes a
// replay of the first. Reaching the wrap is only possible by planting the head, which is
// why this is the boundary that shipped broken elsewhere on this project.
func TestRatchetRefusesToWrapTheGenerationCounter(t *testing.T) {
	last := ^uint32(0)
	tree := stNewTree(t, 8)
	r, err := tree.ratchetFor(4, RatchetApplication)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	r.head = last - 2

	produced := []uint32{}
	var refusal error
	for range 5 {
		generation, keys, err := r.step()
		if err != nil {
			refusal = err
			if keys != nil {
				t.Fatalf("an exhausted step returned key material as well as %v", err)
			}
			break
		}
		produced = append(produced, generation)
	}
	if !errors.Is(refusal, ErrRatchetExhausted) {
		t.Fatalf("the step past the end of the counter answered %v, want ErrRatchetExhausted", refusal)
	}
	if want := []uint32{last - 2, last - 1, last}; !slices.Equal(produced, want) {
		t.Fatalf("the ratchet produced generations %v, want %v -- a zero in that list is the counter wrapping", produced, want)
	}
	if r.head != last {
		t.Fatalf("the head is %d after exhaustion, want it parked at %d; a head below that reclassifies every consumed generation as future", r.head, last)
	}
	if !r.exhausted {
		t.Fatal("the ratchet is not marked exhausted, so the next step will hand out a generation again")
	}
	// and the receiving path agrees rather than looping: an old generation is consumed, the
	// last one is exhausted, and neither produces a key.
	if _, err := r.keyFor(0); !errors.Is(err, ErrRatchetGenerationConsumed) {
		t.Fatalf("generation 0 on an exhausted ratchet answered %v, want ErrRatchetGenerationConsumed", err)
	}
	if _, err := r.keyFor(last); !errors.Is(err, ErrRatchetExhausted) {
		t.Fatalf("generation %d on an exhausted ratchet answered %v, want ErrRatchetExhausted", last, err)
	}
}

// TestRatchetSpentSecretIsErasedInPlaceAndTheSuccessorIsNotThePredecessor is the forward
// secrecy half of the ratchet and the half no correctness test can see.
//
// The spent secret is held as an ALIAS and not as a copy. An in place erasure is invisible
// to a copy -- the plan's own TestRatchetStepDerivesKeyNonceAndSuccessor takes one, and
// passes unchanged against a step that never calls zeroizeSecret -- so the only way to
// observe it is to keep the slice header the ratchet itself was holding.
func TestRatchetSpentSecretIsErasedInPlaceAndTheSuccessorIsNotThePredecessor(t *testing.T) {
	observed := 0
	for _, kind := range stRatchetKinds() {
		tree := stNewTree(t, 8)
		r, err := tree.ratchetFor(7, kind)
		if err != nil {
			t.Fatalf("ratchetFor: %v", err)
		}
		for step := range 8 {
			spent := r.secret
			before := append([]byte(nil), spent...)
			if stAllZero(before) {
				t.Fatalf("the ratchet secret before step %d is already a run of zeros, so this step could observe no erasure", step)
			}
			if _, _, err := r.step(); err != nil {
				t.Fatalf("step %d: %v", step, err)
			}
			if !stAllZero(spent) {
				t.Fatalf("the spent ratchet secret of generation %d survived the step as %x; anyone taking the process now recomputes every generation from here back",
					step, spent)
			}
			if bytes.Equal(r.secret, before) {
				t.Fatalf("the successor at generation %d is its own predecessor, so the ratchet is not advancing", step)
			}
			if stAllZero(r.secret) {
				t.Fatalf("the successor at generation %d is a run of zeros, which every party in the world can compute", step)
			}
			observed++
		}
	}
	if observed != 8*len(stRatchetKinds()) {
		t.Fatalf("observed %d steps, want %d", observed, 8*len(stRatchetKinds()))
	}
}

// TestRatchetRetainsNoSpentSecretInAnyFieldOfTheTreesType is the other half of the same
// claim, at the scope this file learned to use: the TYPE and not a field name.
//
// The alias test next door sees a secret that was overwritten. It cannot see one that was
// COPIED somewhere first -- an archive map, a debug slice, a second field added by a later
// task -- and that shape passed all 750 tests of this package before secretTreeRetainedBytes
// existed. This one walks everything the tree still reaches.
func TestRatchetRetainsNoSpentSecretInAnyFieldOfTheTreesType(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	const leafCount = LeafCount(8)
	const leaf = LeafIndex(2)
	const steps = 12

	tree := stNewTree(t, leafCount)
	r, err := tree.ratchetFor(leaf, RatchetApplication)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	// the chain this test derives for itself: chain[i] is the secret generation i is derived
	// from, so chain[0:steps] are all spent by the end and chain[steps] is the live one.
	chain := [][]byte{stRatchetRoot(t, crypto, encryptionSecret, leafCount, leaf, RatchetApplication)}
	for generation := uint32(0); generation < steps; generation++ {
		chain = append(chain, crypto.DeriveTreeSecret(chain[generation], "secret", generation, crypto.HashSize()))
	}
	for at := range steps {
		if _, _, err := r.step(); err != nil {
			t.Fatalf("step %d: %v", at, err)
		}
	}
	if !bytes.Equal(r.secret, chain[steps]) {
		t.Fatalf("the ratchet is not on the chain this test derived, so nothing below is measuring the right values")
	}

	held := secretTreeRetainedBytes(t, tree)
	for spent := range steps {
		for _, one := range held {
			if bytes.Contains(one.carried, chain[spent]) {
				t.Fatalf("the ratchet secret of generation %d is still held at %s after %d further steps",
					spent, one.where, steps-spent)
			}
		}
	}
	// the control: the LIVE secret is reachable, so "not found" above means erased rather
	// than meaning this walk never looked inside the ratchets at all.
	found := ""
	for _, one := range held {
		if bytes.Contains(one.carried, chain[steps]) {
			found = one.where
			break
		}
	}
	if found == "" {
		t.Fatal("the walk did not find the ratchet's live secret anywhere on the tree, so the sweep above holds vacuously")
	}
}

// TestNoTwoRatchetsShareAKeyNoncePairAtAnyGeneration is the cross-sender half of the AEAD
// safety property.
//
// Every generation of every leaf's two ratchets is collected into one table, so a descent
// that gave two leaves the same node secret, a table keyed on less than the leaf and the
// type, or a root expansion that ignored its label all land as a collision here. It is the
// defect that is silent by construction: two senders each producing a perfectly correct
// sequence, which happens to be the same sequence.
func TestNoTwoRatchetsShareAKeyNoncePairAtAnyGeneration(t *testing.T) {
	const leafCount = LeafCount(8)
	const generations = 64
	tree := stNewTree(t, leafCount)
	leaves := stLeavesOf(t, leafCount)
	kinds := stRatchetKinds()

	type owner struct {
		leaf       LeafIndex
		kind       RatchetType
		generation uint32
	}
	pairs := map[string]owner{}
	nonces := map[string]owner{}
	for _, leaf := range leaves {
		for _, kind := range kinds {
			for want := uint32(0); want < generations; want++ {
				generation, key, nonce, err := tree.NextSenderKey(leaf, kind)
				if err != nil {
					t.Fatalf("NextSenderKey(%d, %d): %v", leaf, kind, err)
				}
				if generation != want {
					t.Fatalf("leaf %d kind %d produced generation %d, want %d", leaf, kind, generation, want)
				}
				mine := owner{leaf: leaf, kind: kind, generation: generation}
				if previous, ok := pairs[string(key)+"|"+string(nonce)]; ok {
					t.Fatalf("leaf %d kind %d generation %d reaches the same key and nonce pair as leaf %d kind %d generation %d",
						mine.leaf, mine.kind, mine.generation, previous.leaf, previous.kind, previous.generation)
				}
				pairs[string(key)+"|"+string(nonce)] = mine
				// the nonce alone as well. Two senders on one nonce is safe only while their
				// keys differ, and "their keys differ" is the thing above that would already
				// have failed -- so a nonce collision here is a warning that a single further
				// defect completes the break.
				if previous, ok := nonces[string(nonce)]; ok {
					t.Fatalf("leaf %d kind %d generation %d repeats the nonce of leaf %d kind %d generation %d",
						mine.leaf, mine.kind, mine.generation, previous.leaf, previous.kind, previous.generation)
				}
				nonces[string(nonce)] = mine
			}
		}
	}
	if want := len(leaves) * len(kinds) * generations; len(pairs) != want {
		t.Fatalf("collected %d distinct pairs over %d leaves, %d ratchet types and %d generations, want %d",
			len(pairs), len(leaves), len(kinds), generations, want)
	}
}

// TestSenderAndReceiverAgreeForEveryLeafAndKindAndDisagreeAcrossThem is the routing half:
// the receiving path must reach the SAME key the sending path produced for that leaf and
// that type, and a different one for every other leaf and type.
//
// The negative half is what makes it a routing test rather than a round trip. A ReceiverKey
// that ignored its leaf argument would agree with a sender for one leaf and be wrong for the
// other seven, and a round trip over a single leaf reports that as green.
func TestSenderAndReceiverAgreeForEveryLeafAndKindAndDisagreeAcrossThem(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	const leafCount = LeafCount(8)
	const generations = 3
	leaves := stLeavesOf(t, leafCount)
	kinds := stRatchetKinds()

	sender, err := NewSecretTree(crypto, leafCount, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	type slot struct {
		leaf       LeafIndex
		kind       RatchetType
		generation uint32
	}
	sent := map[slot][]byte{}
	for _, leaf := range leaves {
		for _, kind := range kinds {
			for range generations {
				generation, key, nonce, err := sender.NextSenderKey(leaf, kind)
				if err != nil {
					t.Fatalf("NextSenderKey: %v", err)
				}
				sent[slot{leaf: leaf, kind: kind, generation: generation}] = append(append([]byte(nil), key...), nonce...)
			}
		}
	}

	matched := 0
	for at, want := range sent {
		receiver, err := NewSecretTree(crypto, leafCount, encryptionSecret)
		if err != nil {
			t.Fatalf("NewSecretTree: %v", err)
		}
		key, nonce, err := receiver.ReceiverKey(at.leaf, at.kind, at.generation)
		if err != nil {
			t.Fatalf("ReceiverKey(%d, %d, %d): %v", at.leaf, at.kind, at.generation, err)
		}
		if got := append(append([]byte(nil), key...), nonce...); !bytes.Equal(got, want) {
			t.Fatalf("leaf %d kind %d generation %d: the receiver derived %x and the sender produced %x",
				at.leaf, at.kind, at.generation, got, want)
		}
		matched++
		// and every other slot answers something else, so the agreement above is about this
		// leaf and this type rather than about the tree having one keystream.
		for other := range sent {
			if other == at {
				continue
			}
			if bytes.Equal(sent[other], want) {
				t.Fatalf("leaf %d kind %d generation %d and leaf %d kind %d generation %d produce the same key and nonce",
					at.leaf, at.kind, at.generation, other.leaf, other.kind, other.generation)
			}
		}
	}
	if want := len(leaves) * len(kinds) * generations; matched != want {
		t.Fatalf("matched %d slots, want %d", matched, want)
	}
}

// TestRatchetReadsItsKeyAndNonceWidthsOffTheProviderItWasHanded is the differential the
// registry cannot supply, for the two lengths the ratchet reads on every single step.
//
// Both registered suites fix Nn at 12, and 0x0003 fixes Nk at 32 -- which is also Nh, also
// the length of every vector in this file, and also the literal a body would have written
// down. So inside the registry a read of NonceSize() and a written 12 are one number, and
// nothing else in this tree separates them. This provider is assembled at an Nk and an Nn no
// registered suite has, so each substitution is a different number rather than the same one.
func TestRatchetReadsItsKeyAndNonceWidthsOffTheProviderItWasHanded(t *testing.T) {
	crypto := &suiteCryptoProvider{params: &ksWelcomeSyntheticParams, random: rand.Reader}
	nk, nn, nh := crypto.KeySize(), crypto.NonceSize(), crypto.HashSize()
	// the substitutions this provider has to be able to see. A length here that coincided
	// with another would leave the assertions below satisfied by the literal they exist to
	// catch, which is how a differential goes quiet without failing.
	for _, one := range []struct {
		name  string
		value int
	}{
		{name: "this suite's Nn", value: nn},
		{name: "this suite's Nh", value: nh},
		{name: "the registered chacha suite's Nk", value: 32},
		{name: "the registered nonce size", value: 12},
	} {
		if one.value == nk {
			t.Fatalf("%s is %d, the same as this fixture's Nk, so this differential is blind to it", one.name, one.value)
		}
	}
	for _, one := range []struct {
		name  string
		value int
	}{
		{name: "this suite's Nh", value: nh},
		{name: "the registered nonce size", value: 12},
	} {
		if one.value == nn {
			t.Fatalf("%s is %d, the same as this fixture's Nn, so this differential is blind to it", one.name, one.value)
		}
	}

	encryptionSecret := bytes.Repeat([]byte{0x5a}, nh)
	tree, err := NewSecretTree(crypto, 8, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	generation, key, nonce, err := tree.NextSenderKey(5, RatchetApplication)
	if err != nil {
		t.Fatalf("NextSenderKey: %v", err)
	}
	if generation != 0 {
		t.Fatalf("generation = %d, want 0", generation)
	}
	if len(key) != nk {
		t.Fatalf("the key is %d bytes for a suite whose Nk is %d", len(key), nk)
	}
	if len(nonce) != nn {
		t.Fatalf("the nonce is %d bytes for a suite whose Nn is %d", len(nonce), nn)
	}
	r, err := tree.ratchetFor(5, RatchetApplication)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	if len(r.secret) != nh {
		t.Fatalf("the successor secret is %d bytes for a suite whose Nh is %d", len(r.secret), nh)
	}

	// and the width moved INSIDE the preimage with it, not only in the size of the answer:
	// KDFLabel carries the length, so a body deriving 32 bytes and a body deriving Nk bytes
	// disagree in every byte rather than in a prefix.
	root := stRatchetRoot(t, crypto, encryptionSecret, 8, 5, RatchetApplication)
	if want := crypto.DeriveTreeSecret(root, "key", 0, nk); !bytes.Equal(key, want) {
		t.Fatalf("the key is %x, want %x", key, want)
	}
	if want := crypto.DeriveTreeSecret(root, "nonce", 0, nn); !bytes.Equal(nonce, want) {
		t.Fatalf("the nonce is %x, want %x", nonce, want)
	}
	atThirtyTwo := crypto.DeriveTreeSecret(root, "key", 0, 32)
	if bytes.Equal(atThirtyTwo[:nk], key) {
		t.Fatalf("deriving 32 bytes and deriving %d agree on their first %d, so a hardcoded key size would be a truncation this test could not see", nk, nk)
	}
	atTwelve := crypto.DeriveTreeSecret(root, "nonce", 0, 12)
	if bytes.Equal(atTwelve[:nn], nonce) {
		t.Fatalf("deriving 12 bytes and deriving %d agree on their first %d, so a hardcoded nonce size would be a truncation this test could not see", nn, nn)
	}

	// the receiving path reads the same two lengths; it is a separate call site and has
	// silently disagreed with its sending twin elsewhere on this project.
	receiver, err := NewSecretTree(crypto, 8, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	gotKey, gotNonce, err := receiver.ReceiverKey(5, RatchetApplication, 0)
	if err != nil {
		t.Fatalf("ReceiverKey: %v", err)
	}
	if len(gotKey) != nk || len(gotNonce) != nn {
		t.Fatalf("the receiver produced a %d byte key and a %d byte nonce, want %d and %d", len(gotKey), len(gotNonce), nk, nn)
	}
}

// ---------------------------------------------------------------------------
// the generation window: its bound, its eviction and its edges
// ---------------------------------------------------------------------------

// TestReceiverKeySkipBoundIsExactlyMaxGenerationSkip pins both sides of the bound, DERIVED
// from the constant rather than typed.
//
// Off by one in the permissive direction is still a bound and costs an extra thousand KDF
// calls; off by one the other way drops a message that legitimately arrived, and the sender
// has no way to learn it happened. The bound is also checked to be measured from the HEAD
// and not from zero, which is the version that silently stops working after the first
// thousand messages of an epoch.
func TestReceiverKeySkipBoundIsExactlyMaxGenerationSkip(t *testing.T) {
	tree := stNewTree(t, 8)
	if _, _, err := tree.ReceiverKey(1, RatchetApplication, MaxGenerationSkip); err != nil {
		t.Fatalf("a skip of exactly MaxGenerationSkip (%d) was refused: %v", MaxGenerationSkip, err)
	}
	if _, _, err := tree.ReceiverKey(3, RatchetApplication, MaxGenerationSkip+1); !errors.Is(err, ErrRatchetGenerationTooFarAhead) {
		t.Fatalf("a skip of MaxGenerationSkip+1 (%d) answered %v, want ErrRatchetGenerationTooFarAhead", MaxGenerationSkip+1, err)
	}
	// leaf 1's head is now one past the generation it served, and the same distance ahead of
	// THAT is accepted again.
	head, err := tree.SenderGeneration(1, RatchetApplication)
	if err != nil {
		t.Fatalf("SenderGeneration: %v", err)
	}
	if head != MaxGenerationSkip+1 {
		t.Fatalf("the head is %d after serving generation %d", head, MaxGenerationSkip)
	}
	if _, _, err := tree.ReceiverKey(1, RatchetApplication, head+MaxGenerationSkip); err != nil {
		t.Fatalf("a skip of MaxGenerationSkip from a head of %d was refused: %v", head, err)
	}
	moved, err := tree.SenderGeneration(1, RatchetApplication)
	if err != nil {
		t.Fatalf("SenderGeneration: %v", err)
	}
	if moved <= head {
		t.Fatalf("the head did not move past %d, so the check below is the same one as above", head)
	}
	if _, _, err := tree.ReceiverKey(1, RatchetApplication, moved+MaxGenerationSkip+1); !errors.Is(err, ErrRatchetGenerationTooFarAhead) {
		t.Fatalf("a skip of MaxGenerationSkip+1 from a head of %d answered %v, want ErrRatchetGenerationTooFarAhead", moved, err)
	}
}

// TestReceiverKeyWindowIsBoundedAndEvictsTheOldest asserts the retained skipped keys are
// capped at RatchetWindowSize and that what goes when the cap is reached is the oldest.
//
// Both edges matter and they fail in opposite directions. A window that never evicts is a
// memory bound chosen by whoever sends the messages: one silent sender, four billion
// retained keys. A window that evicts too eagerly throws away messages that legitimately
// arrived out of order, which the sender never learns about.
//
// The number of requests is DERIVED from the two constants. The plan's own version of this
// test asked for exactly MaxGenerationSkip and then required generation 0 to be gone -- with
// the two constants equal, that request retains exactly RatchetWindowSize keys and evicts
// nothing, so the assertion could not hold against any implementation. What is written here
// computes how many maximal skips it takes to exceed the window, and refuses to run if that
// count would not exceed it.
func TestReceiverKeyWindowIsBoundedAndEvictsTheOldest(t *testing.T) {
	tree := stNewTree(t, 8)
	const leaf = LeafIndex(1)
	const kind = RatchetApplication

	// each maximal skip retains exactly MaxGenerationSkip keys, so this is how many of them
	// it takes to push the retained set past the window.
	hops := (RatchetWindowSize + int(MaxGenerationSkip)) / int(MaxGenerationSkip)
	retainedWithoutEviction := hops * int(MaxGenerationSkip)
	if retainedWithoutEviction <= RatchetWindowSize {
		t.Fatalf("this sequence retains at most %d keys and the window holds %d, so it could not observe an eviction",
			retainedWithoutEviction, RatchetWindowSize)
	}

	requested := []uint32{}
	head := uint32(0)
	for range hops {
		asked := head + MaxGenerationSkip
		if _, _, err := tree.ReceiverKey(leaf, kind, asked); err != nil {
			t.Fatalf("ReceiverKey(%d): %v", asked, err)
		}
		requested = append(requested, asked)
		head = asked + 1
	}

	r, err := tree.ratchetFor(leaf, kind)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	if len(r.window) > RatchetWindowSize {
		t.Fatalf("the window holds %d entries after %d maximal skips, want at most %d; unbounded retention is a memory bound the sender chooses",
			len(r.window), hops, RatchetWindowSize)
	}
	if len(r.window) != RatchetWindowSize {
		t.Fatalf("the window holds %d entries after overflowing, want exactly its bound of %d; evicting more than it has to loses messages that arrived",
			len(r.window), RatchetWindowSize)
	}

	// every generation this sequence skipped and did not consume, oldest first.
	skipped := []uint32{}
	for generation := uint32(0); generation < head; generation++ {
		if !slices.Contains(requested, generation) {
			skipped = append(skipped, generation)
		}
	}
	want := skipped[len(skipped)-RatchetWindowSize:]
	if got := slices.Sorted(maps.Keys(r.window)); !slices.Equal(got, want) {
		t.Fatalf("the window retained generations %d..%d, want the newest %d, %d..%d",
			got[0], got[len(got)-1], RatchetWindowSize, want[0], want[len(want)-1])
	}

	// and the eviction is visible through the API rather than only in the field: the oldest
	// skipped generation now reads as consumed, which is the visible gap the product needs,
	// and the newest retained one is still usable.
	if _, _, err := tree.ReceiverKey(leaf, kind, skipped[0]); !errors.Is(err, ErrRatchetGenerationConsumed) {
		t.Fatalf("generation %d survived a window that overflowed: err = %v", skipped[0], err)
	}
	if _, _, err := tree.ReceiverKey(leaf, kind, want[len(want)-1]); err != nil {
		t.Fatalf("the newest retained generation %d was not usable: %v", want[len(want)-1], err)
	}
}

// TestReceiverKeyWindowStaysBoundedUnderARepeatedMaximalSkip is the memory claim over a
// sender that never stops skipping, rather than over the single overflow next door.
func TestReceiverKeyWindowStaysBoundedUnderARepeatedMaximalSkip(t *testing.T) {
	tree := stNewTree(t, 8)
	const leaf = LeafIndex(3)
	const kind = RatchetHandshake
	r, err := tree.ratchetFor(leaf, kind)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	// enough rounds to exceed the window several times over, derived so the count follows the
	// constants rather than standing beside them.
	rounds := 3 * (RatchetWindowSize + int(MaxGenerationSkip)) / int(MaxGenerationSkip)
	head := uint32(0)
	for at := range rounds {
		asked := head + MaxGenerationSkip
		if _, _, err := tree.ReceiverKey(leaf, kind, asked); err != nil {
			t.Fatalf("ReceiverKey(%d): %v", asked, err)
		}
		head = asked + 1
		if len(r.window) > RatchetWindowSize {
			t.Fatalf("after %d maximal skips the window holds %d entries, want at most %d", at+1, len(r.window), RatchetWindowSize)
		}
	}
	if rounds*int(MaxGenerationSkip) <= RatchetWindowSize {
		t.Fatalf("this sequence never exceeds the window, so the bound above was never tested")
	}
	if len(r.window) != RatchetWindowSize {
		t.Fatalf("the window settled at %d entries, want its bound of %d", len(r.window), RatchetWindowSize)
	}
}

// TestSecretTreeZeroizeLeavesNoRatchetOrWindowSecretAnywhereOnTheType is Zeroize at the
// scope of the type.
//
// The plan's TestSecretTreeZeroize reads two field names, tree.nodes and one ratchet's
// secret. Neither reaches the RETAINED WINDOW KEYS, which after an out of order delivery
// are live AEAD keys sitting in a map -- and an epoch leaving PastEpochWindow with its
// window keys intact is the same failure as one leaving with its ratchet secrets intact.
func TestSecretTreeZeroizeLeavesNoRatchetOrWindowSecretAnywhereOnTheType(t *testing.T) {
	tree := stNewTree(t, 8)
	// a sender, and a receiver that skipped -- so the tree holds ratchet secrets, retained
	// window keys and node secrets for the leaves nobody has touched.
	if _, _, _, err := tree.NextSenderKey(0, RatchetApplication); err != nil {
		t.Fatalf("NextSenderKey: %v", err)
	}
	if _, _, err := tree.ReceiverKey(2, RatchetHandshake, 6); err != nil {
		t.Fatalf("ReceiverKey: %v", err)
	}

	targets := map[string]string{}
	windowKeys := 0
	for at, r := range tree.ratchets {
		targets[string(r.secret)] = fmt.Sprintf("the ratchet secret of leaf %d kind %d", at.leaf, at.kind)
		for generation, keys := range r.window {
			targets[string(keys.key)] = fmt.Sprintf("the retained key of leaf %d kind %d generation %d", at.leaf, at.kind, generation)
			targets[string(keys.nonce)] = fmt.Sprintf("the retained nonce of leaf %d kind %d generation %d", at.leaf, at.kind, generation)
			windowKeys++
		}
	}
	for node, secret := range tree.nodes {
		targets[string(secret)] = fmt.Sprintf("the node secret of node %d", node)
	}
	if windowKeys == 0 {
		t.Fatal("no window keys were retained, so this test cannot say anything about them")
	}
	if len(targets) < 4 {
		t.Fatalf("only %d secrets to check, which is not a tree in the state this test needs", len(targets))
	}

	// the control: every one of them is reachable BEFORE the erasure, so an absence
	// afterwards is the erasure and not a walk that stopped looking.
	before := secretTreeRetainedBytes(t, tree)
	for secret, what := range targets {
		found := false
		for _, one := range before {
			if bytes.Contains(one.carried, []byte(secret)) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("the walk does not reach %s even before Zeroize, so its absence afterwards would prove nothing", what)
		}
	}

	tree.Zeroize()

	for _, one := range secretTreeRetainedBytes(t, tree) {
		for secret, what := range targets {
			if bytes.Contains(one.carried, []byte(secret)) {
				t.Fatalf("%s survived Zeroize and is still held at %s", what, one.where)
			}
		}
	}
}

// TestEveryExportedSecretTreeMethodRefusesAfterZeroize derives the class rather than naming
// it: every exported method of this type that can report an error must report ErrEpochErased
// once the epoch has been erased, and any method that cannot report an error must return
// nothing that could carry a secret.
//
// Enumerating the three methods that exist today is the shape this project keeps having to
// undo -- a table named "every rule" holding five of six. Reading the method set means the
// exported surface p6 and later plans add arrives already covered, and an added method that
// hands back key material with no way to refuse fails HERE rather than at the epoch that
// needed the refusal.
//
// The reason a refusal is required at all: Zeroize overwrites every node secret and every
// ratchet secret with Nh zero bytes, and expanding a run of zeros is not a weak derivation,
// it is one every party in the world can perform. A method that answered from an erased tree
// would return a real looking key, with no error, that offers no confidentiality at all.
func TestEveryExportedSecretTreeMethodRefusesAfterZeroize(t *testing.T) {
	errorType := reflect.TypeOf((*error)(nil)).Elem()
	pointer := reflect.TypeOf(&SecretTree{})
	if pointer.NumMethod() == 0 {
		t.Fatal("*SecretTree has no exported methods, so this gate read the wrong type")
	}

	call := func(tree *SecretTree, method reflect.Method) []reflect.Value {
		arguments := []reflect.Value{reflect.ValueOf(tree)}
		for at := 1; at < method.Type.NumIn(); at++ {
			arguments = append(arguments, reflect.Zero(method.Type.In(at)))
		}
		return method.Func.Call(arguments)
	}

	// the control, on a tree that was never erased. Without it a build where every method
	// returned ErrEpochErased unconditionally -- or where errors.Is answered yes to
	// everything -- would satisfy the sweep below completely.
	live := stNewTree(t, 8)
	for at := range pointer.NumMethod() {
		method := pointer.Method(at)
		for _, result := range call(live, method) {
			if !result.Type().Implements(errorType) || result.IsNil() {
				continue
			}
			if errors.Is(result.Interface().(error), ErrEpochErased) {
				t.Fatalf("%s answered ErrEpochErased on a tree that was never zeroized", method.Name)
			}
		}
	}

	erased := stNewTree(t, 8)
	if _, _, _, err := erased.NextSenderKey(0, RatchetApplication); err != nil {
		t.Fatalf("NextSenderKey: %v", err)
	}
	erased.Zeroize()

	refusals := 0
	for at := range pointer.NumMethod() {
		method := pointer.Method(at)
		refused := false
		carries := []string{}
		for _, result := range call(erased, method) {
			if result.Type().Implements(errorType) {
				if result.IsNil() {
					continue
				}
				if err := result.Interface().(error); !errors.Is(err, ErrEpochErased) {
					t.Errorf("%s on an erased tree answered %v, want ErrEpochErased", method.Name, err)
				} else {
					refused = true
					refusals++
				}
				continue
			}
			switch result.Kind() {
			case reflect.Slice, reflect.Array, reflect.String, reflect.Pointer,
				reflect.Interface, reflect.Map, reflect.Struct:
				carries = append(carries, result.Type().String())
			}
		}
		if !refused && len(carries) != 0 {
			t.Errorf("%s returns %v on an erased tree with no error to refuse through, so it can hand back key material derived from a run of zeros",
				method.Name, carries)
		}
	}
	if refusals == 0 {
		t.Fatal("no exported method refused an erased tree, so this gate is reporting on nothing")
	}
}

// TestZeroizeIsIdempotentAndRefusesEveryLaterDerivation states the two halves of the flag in
// terms a caller sees, so the field is not the only thing observing it.
func TestZeroizeIsIdempotentAndRefusesEveryLaterDerivation(t *testing.T) {
	tree := stNewTree(t, 8)
	if _, _, _, err := tree.NextSenderKey(1, RatchetApplication); err != nil {
		t.Fatalf("NextSenderKey: %v", err)
	}
	tree.Zeroize()
	tree.Zeroize()

	// a leaf that had a ratchet, and one that never did: the refusal must not depend on
	// whether the tree happens to hold a cached ratchet for the leaf being asked about.
	for _, leaf := range []LeafIndex{1, 6} {
		for _, kind := range stRatchetKinds() {
			if _, _, _, err := tree.NextSenderKey(leaf, kind); !errors.Is(err, ErrEpochErased) {
				t.Errorf("NextSenderKey(%d, %d) after Zeroize answered %v, want ErrEpochErased", leaf, kind, err)
			}
			if _, _, err := tree.ReceiverKey(leaf, kind, 0); !errors.Is(err, ErrEpochErased) {
				t.Errorf("ReceiverKey(%d, %d, 0) after Zeroize answered %v, want ErrEpochErased", leaf, kind, err)
			}
			if _, err := tree.SenderGeneration(leaf, kind); !errors.Is(err, ErrEpochErased) {
				t.Errorf("SenderGeneration(%d, %d) after Zeroize answered %v, want ErrEpochErased", leaf, kind, err)
			}
		}
	}
	// the unexported path underneath refuses too, so a later task reaching for the node
	// secrets directly cannot walk around the flag.
	if _, err := tree.takeLeafSecret(6); !errors.Is(err, ErrEpochErased) {
		t.Errorf("takeLeafSecret after Zeroize answered %v, want ErrEpochErased", err)
	}
}

// TestRatchetForRefusesAnUnknownRatchetType asserts the zero value and every code point past
// the two named ones are refused rather than defaulted.
//
// A default would be the worst kind of correct: a ContentType decoded one layer up that fell
// through to "handshake" would put an application message on the handshake ratchet, and both
// streams would then draw from one keystream while every individual derivation stayed right.
//
// It holds every refusal to the FIRST of ratchetFor's two, the way
// TestSecretTreeASecondTakeIsAlwaysTheConsumedRefusalAndNeverTheInvariantOne does next door.
// The second -- reached when the type check admitted a kind the stores below do not write --
// is unreachable, and it exists because the bare map read that stood in its place answered a
// nil ratchet and a NIL ERROR, which the caller then steps. Measured, on the commit that
// added it: with the type check replaced by a constant false and the two refusals
// indistinguishable, this test passed, because the invariant refusal caught what the type
// check no longer did and answered the same sentinel. Two guards over one property with no
// way to tell which fired is one guard that can be deleted silently.
func TestRatchetForRefusesAnUnknownRatchetType(t *testing.T) {
	// the control on the matcher: the two refusals differ only in the sentinel the second
	// wraps, so an errors.Is that could not see it through the wrapping would report every
	// refusal as the ordinary one no matter which return produced it.
	both := fmt.Errorf("%w: ratchet type 9: %w", ErrSecretTreeLeafOutOfRange, errRatchetTypeHasNoRoot)
	if !errors.Is(both, ErrSecretTreeLeafOutOfRange) || !errors.Is(both, errRatchetTypeHasNoRoot) {
		t.Fatalf("the two sentinels are not both visible through %v, so this test cannot tell the two refusals apart", both)
	}
	if errors.Is(fmt.Errorf("%w: ratchet type 9", ErrSecretTreeLeafOutOfRange), errRatchetTypeHasNoRoot) {
		t.Fatal("the ordinary refusal answers to the invariant sentinel, so every refusal below would read as the invariant one")
	}

	known := stRatchetKinds()
	refused := 0
	for probe := 0; probe < 256; probe++ {
		kind := RatchetType(probe)
		tree := stNewTree(t, 8)
		_, _, _, err := tree.NextSenderKey(0, kind)
		if slices.Contains(known, kind) {
			if err != nil {
				t.Fatalf("ratchet type %d is one of this package's own and was refused: %v", kind, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("ratchet type %d was accepted, so a decoded content type that fell through has a keystream to share", kind)
		}
		if !errors.Is(err, ErrSecretTreeLeafOutOfRange) {
			t.Fatalf("ratchet type %d was refused with %v, want ErrSecretTreeLeafOutOfRange", kind, err)
		}
		if errors.Is(err, errRatchetTypeHasNoRoot) {
			t.Fatalf("ratchet type %d was refused by the post store return, which is reachable only if the type check above it stopped admitting exactly the kinds the stores write: %v", kind, err)
		}
		refused++
	}
	if want := 256 - len(known); refused != want {
		t.Fatalf("refused %d ratchet types, want %d", refused, want)
	}
}

// TestSenderAndReceiverPathsShareOneRatchetPerLeafAndKind asserts the two entry points reach
// the SAME ratchet, so a leaf that both sends and receives on one tree cannot end up with two
// heads over one keystream.
func TestSenderAndReceiverPathsShareOneRatchetPerLeafAndKind(t *testing.T) {
	tree := stNewTree(t, 8)
	if _, _, _, err := tree.NextSenderKey(4, RatchetApplication); err != nil {
		t.Fatalf("NextSenderKey: %v", err)
	}
	head, err := tree.SenderGeneration(4, RatchetApplication)
	if err != nil {
		t.Fatalf("SenderGeneration: %v", err)
	}
	if head != 1 {
		t.Fatalf("head = %d after one send, want 1", head)
	}
	// generation 0 has been handed out already, so the receiving path must call it consumed
	// rather than deriving it a second time from a ratchet of its own.
	if _, _, err := tree.ReceiverKey(4, RatchetApplication, 0); !errors.Is(err, ErrRatchetGenerationConsumed) {
		t.Fatalf("ReceiverKey(0) after the sender took it answered %v, want ErrRatchetGenerationConsumed", err)
	}
	// and the other type of the same leaf is untouched by all of it.
	if other, err := tree.SenderGeneration(4, RatchetHandshake); err != nil || other != 0 {
		t.Fatalf("the handshake ratchet of leaf 4 is at generation %d (err %v), want 0", other, err)
	}
}

// TestEvictedWindowKeysAreErasedInPlace is the eviction half of the window's erasure, and it
// is written with ALIASES because nothing else can see it.
//
// A key evicted from the window is deleted from the map, so from that moment nothing on the
// tree reaches it and the type-derived walk this file scopes every other forward secrecy
// claim by reports it gone whether it was overwritten or merely dropped. Measured: with both
// zeroizeSecret calls removed from prune, every test in this package still passed. Holding
// the slice header the window itself was holding is the only way to ask the question.
func TestEvictedWindowKeysAreErasedInPlace(t *testing.T) {
	tree := stNewTree(t, 8)
	const leaf = LeafIndex(1)
	const kind = RatchetApplication
	if _, _, err := tree.ReceiverKey(leaf, kind, MaxGenerationSkip); err != nil {
		t.Fatalf("ReceiverKey(%d): %v", MaxGenerationSkip, err)
	}
	r, err := tree.ratchetFor(leaf, kind)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	if len(r.window) != RatchetWindowSize {
		t.Fatalf("the window holds %d entries and this test needs it exactly full at %d", len(r.window), RatchetWindowSize)
	}
	held := map[uint32][][]byte{}
	for generation, keys := range r.window {
		held[generation] = [][]byte{keys.key, keys.nonce}
		if stAllZero(keys.key) || stAllZero(keys.nonce) {
			t.Fatalf("the retained key material of generation %d is already zero, so an erasure here would be invisible", generation)
		}
	}

	// a SMALL further skip, so some entries are evicted and some survive. A skip large enough
	// to clear the whole window would leave the survivor half of this test with nothing in it.
	const extra = uint32(4)
	if int(extra) >= RatchetWindowSize || extra > MaxGenerationSkip {
		t.Fatalf("a further skip of %d cannot both overflow a window of %d and leave survivors", extra, RatchetWindowSize)
	}
	head, err := tree.SenderGeneration(leaf, kind)
	if err != nil {
		t.Fatalf("SenderGeneration: %v", err)
	}
	if _, _, err := tree.ReceiverKey(leaf, kind, head+extra); err != nil {
		t.Fatalf("ReceiverKey(%d): %v", head+extra, err)
	}

	evicted, survived := 0, 0
	for generation, pair := range held {
		if _, ok := r.window[generation]; ok {
			survived++
			if stAllZero(pair[0]) || stAllZero(pair[1]) {
				t.Fatalf("generation %d is still in the window and its key material has been erased under it", generation)
			}
			continue
		}
		evicted++
		if !stAllZero(pair[0]) {
			t.Fatalf("the key of evicted generation %d survives the eviction as %x", generation, pair[0])
		}
		if !stAllZero(pair[1]) {
			t.Fatalf("the nonce of evicted generation %d survives the eviction as %x", generation, pair[1])
		}
	}
	if evicted != int(extra) {
		t.Fatalf("%d entries were evicted by a further skip of %d, want %d", evicted, extra, extra)
	}
	if survived != RatchetWindowSize-int(extra) {
		t.Fatalf("%d entries survived, want %d; without survivors the control above is vacuous", survived, RatchetWindowSize-int(extra))
	}
}

// TestZeroizeErasesTheRetainedWindowKeysInPlace is the same question for the epoch's end.
//
// Zeroize could satisfy every other test in this file by dropping the window rather than
// erasing it -- measured, with the erase loop replaced by a single clear(), the whole package
// stayed green -- and dropping it leaves live AEAD keys of an epoch that was supposed to be
// gone sitting in whatever the allocator does with them next.
func TestZeroizeErasesTheRetainedWindowKeysInPlace(t *testing.T) {
	tree := stNewTree(t, 8)
	const leaf = LeafIndex(2)
	const kind = RatchetHandshake
	if _, _, err := tree.ReceiverKey(leaf, kind, 6); err != nil {
		t.Fatalf("ReceiverKey: %v", err)
	}
	r, err := tree.ratchetFor(leaf, kind)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	aliases := [][]byte{r.secret}
	for _, keys := range r.window {
		aliases = append(aliases, keys.key, keys.nonce)
	}
	// six skipped generations, each with a key and a nonce, plus the ratchet secret.
	if want := 1 + 2*6; len(aliases) != want {
		t.Fatalf("this ratchet holds %d secrets, want %d", len(aliases), want)
	}
	for at, one := range aliases {
		if stAllZero(one) {
			t.Fatalf("retained secret %d is already zero, so its erasure would be invisible", at)
		}
	}

	tree.Zeroize()

	for at, one := range aliases {
		if !stAllZero(one) {
			t.Fatalf("retained secret %d survived Zeroize as %x", at, one)
		}
	}
	// and it is unreachable as well as erased, so neither half stands in for the other.
	if len(r.window) != 0 {
		t.Fatalf("the window still holds %d entries after Zeroize", len(r.window))
	}
}
