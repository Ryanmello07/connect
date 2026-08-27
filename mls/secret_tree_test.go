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
			return strings.Compare(providerMapKeyOrder(a), providerMapKeyOrder(b))
		})
		for _, key := range keys {
			rendered := providerMapKeyOrder(key)
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
	"stateLock": "the mutex guarding nodes; it holds no value to derive",
	"crypto":    "the provider the caller handed in, which the tree does not choose",
	"nodes":     "the mutable node secrets, whose contents change with every take",
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
