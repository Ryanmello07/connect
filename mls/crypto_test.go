// The provider core: the sizes a suite fixes, the four primitives that carry no label,
// the aead wrappers, and the entropy source everything else draws from.
//
// Three of these have a failure mode no round trip can see, and each is pinned here to a
// published answer rather than to this package's own output. A mac that ignores its key
// still verifies against itself. An extract that reads its arguments in the library's
// order rather than the spec's still derives a stable secret both ends agree on. And a
// random that reverses, rotates or sorts the bytes it read still returns thirty two bytes
// that are never zero and never repeat — sorting them collapses a 256 bit key to about
// 141 bits, which is the defect this package shipped once already, in task 4, behind a
// test that fed its key generator a constant reader.
//
// The known answers therefore come from RFC 4231, RFC 5869 and FIPS 180-4 as the pinned
// toolchain's own crypto/hmac, crypto/hkdf and crypto/sha256 test tables carry them, and
// from the vendored RFC 9180 corpus for the aead. The primitives are the standard
// library's and are tested there; what these pin is this file's wiring, which is where
// the argument order, the key length and the reader live.
package mls

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

// A provider over the process entropy source, with construction failure fatal: a test
// that carried on with a nil provider would panic somewhere that says less.
func mustProvider(t *testing.T, suite CipherSuite) CryptoProvider {
	t.Helper()
	crypto, err := NewCryptoProvider(suite)
	if err != nil {
		t.Fatalf("NewCryptoProvider(%#04x): %v", uint16(suite), err)
	}
	return crypto
}

// A provider over a caller's reader, for everything that asserts what Random consumed.
func mustProviderOver(t *testing.T, suite CipherSuite, random io.Reader) CryptoProvider {
	t.Helper()
	crypto, err := NewCryptoProviderWithRandom(suite, random)
	if err != nil {
		t.Fatalf("NewCryptoProviderWithRandom(%#04x): %v", uint16(suite), err)
	}
	return crypto
}

// What a call panicked with, or nil if it returned. Used rather than a bare defer so a
// table of inputs that must all be refused reads as a table.
func recoveredPanic(call func()) (recovered any) {
	defer func() { recovered = recover() }()
	call()
	return nil
}

// A hex known answer, decoded, with a malformed constant fatal rather than a comparison
// against nothing.
func mustDecodeHex(t *testing.T, name string, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("%s is not hex: %v", name, err)
	}
	if len(decoded) == 0 {
		t.Fatalf("%s decoded to nothing", name)
	}
	return decoded
}

// The sizes, against literals rather than against the registry. Reading Nk back out of
// SuiteParams would pass for a provider that returned the other suite's parameters, which
// is the one mistake a two entry registry exists to expose.
func TestProviderSizes(t *testing.T) {
	for _, testCase := range []struct {
		suite        CipherSuite
		hash, key, n int
	}{
		{suite: CipherSuiteX25519AesGcm128Sha256Ed25519, hash: 32, key: 16, n: 12},
		{suite: CipherSuiteX25519ChaCha20Sha256Ed25519, hash: 32, key: 32, n: 12},
	} {
		crypto := mustProvider(t, testCase.suite)
		if crypto.Suite() != testCase.suite {
			t.Errorf("Suite() = %#04x, want %#04x", uint16(crypto.Suite()), uint16(testCase.suite))
		}
		if crypto.HashSize() != testCase.hash {
			t.Errorf("suite %#04x HashSize() = %d, want %d", uint16(testCase.suite), crypto.HashSize(), testCase.hash)
		}
		if crypto.KeySize() != testCase.key {
			t.Errorf("suite %#04x KeySize() = %d, want %d", uint16(testCase.suite), crypto.KeySize(), testCase.key)
		}
		if crypto.NonceSize() != testCase.n {
			t.Errorf("suite %#04x NonceSize() = %d, want %d", uint16(testCase.suite), crypto.NonceSize(), testCase.n)
		}
		// and the three lengths that are answers about this file rather than about the
		// registry: what Hash, Mac and Extract actually produce
		if got := len(crypto.Hash(nil)); got != testCase.hash {
			t.Errorf("suite %#04x Hash produced %d bytes for a HashSize of %d", uint16(testCase.suite), got, testCase.hash)
		}
		if got := len(crypto.Mac(nil, nil)); got != testCase.hash {
			t.Errorf("suite %#04x Mac produced %d bytes for a HashSize of %d", uint16(testCase.suite), got, testCase.hash)
		}
		if got := len(crypto.Extract(nil, nil)); got != testCase.hash {
			t.Errorf("suite %#04x Extract produced %d bytes for a HashSize of %d", uint16(testCase.suite), got, testCase.hash)
		}
	}
}

// Hash, Mac, Extract and Expand are written against sha256 directly rather than selected
// from the suite, which is right for the two entries the registry holds and would be
// silently wrong for a third. This is the guard, and it reads the registry rather than
// crypto.go: a suite added later whose kdf is not HKDF-SHA256, or whose Nh is not 32,
// fails here rather than deriving every one of its secrets under the wrong hash.
func TestEverySuiteNamesTheHashTheProviderComputes(t *testing.T) {
	suites := Suites()
	if len(suites) == 0 {
		t.Fatal("the registry is empty, so this guard reads nothing")
	}
	for _, suite := range suites {
		params, err := LookupSuite(suite)
		if err != nil {
			t.Fatalf("LookupSuite(%#04x): %v", uint16(suite), err)
		}
		if params.KdfId != HpkeKdfHkdfSha256 {
			t.Errorf("suite %#04x names kdf %#04x, but the provider computes HKDF-SHA256", uint16(suite), uint16(params.KdfId))
		}
		if params.Nh != sha256.Size {
			t.Errorf("suite %#04x has Nh %d, but the provider computes a %d byte hash", uint16(suite), params.Nh, sha256.Size)
		}
	}
}

// Both halves of the refusal. "Every code point is refused" is the other way this can be
// wrong, and it passes the refusal on its own.
func TestProviderRefusesUnknownSuite(t *testing.T) {
	for _, suite := range []CipherSuite{0x0000, 0x0002, 0x0004, 0x0007, 0xffff} {
		crypto, err := NewCryptoProvider(suite)
		if !errors.Is(err, ErrUnknownCipherSuite) {
			t.Errorf("NewCryptoProvider(%#04x) error = %v, want ErrUnknownCipherSuite", uint16(suite), err)
		}
		if crypto != nil {
			t.Errorf("NewCryptoProvider(%#04x) returned a provider alongside %v", uint16(suite), err)
		}
		if crypto, err := NewCryptoProviderWithRandom(suite, rand.Reader); !errors.Is(err, ErrUnknownCipherSuite) || crypto != nil {
			t.Errorf("NewCryptoProviderWithRandom(%#04x) = %v, %v, want nil and ErrUnknownCipherSuite", uint16(suite), crypto, err)
		}
	}
	for _, suite := range Suites() {
		if _, err := NewCryptoProvider(suite); err != nil {
			t.Errorf("NewCryptoProvider(%#04x) refused a registered suite: %v", uint16(suite), err)
		}
	}
}

// FIPS 180-4, as crypto/sha256's own golden table carries it. Hash takes no key and no
// suite, so the only thing that can be wrong about it is which hash it is — and a
// truncated or doubled digest is exactly the shape of mistake a length check misses.
//
// The last three rows are here for their lengths rather than for their bytes. The rows
// above them are all shorter than one sha256 block and shorter than a digest, so a hash
// that read only the first block, or only the first thirty two bytes, agrees with every
// one of them. FIPS 180-2 appendix B's two multi block messages and the sentence from
// RFC 4634 cover 43, 56 and 112 bytes, which reach the second block and past it.
func TestProviderHashMatchesTheFipsGoldens(t *testing.T) {
	for _, testCase := range []struct {
		in  string
		out string
	}{
		{in: "", out: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{in: "a", out: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"},
		{in: "abc", out: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{in: "abcd", out: "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"},
		{in: "Nepal premier won't resign.", out: "7102cfd76e2e324889eece5d6c41921b1e142a4ac5a2692be78803097f6a48d8"},
		{
			in:  "The quick brown fox jumps over the lazy dog",
			out: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
		},
		{
			in:  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			out: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
		},
		{
			in: "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn" +
				"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			out: "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
		},
	} {
		want := mustDecodeHex(t, "the digest of "+testCase.in, testCase.out)
		for _, suite := range Suites() {
			crypto := mustProvider(t, suite)
			if got := crypto.Hash([]byte(testCase.in)); !bytes.Equal(got, want) {
				t.Errorf("suite %#04x Hash(%q) = %x, want %x", uint16(suite), testCase.in, got, want)
			}
		}
	}
	// nil and empty are the same message and must hash alike, which is the input that
	// separates a hash from one substituting a default for a caller that passed none
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	if !bytes.Equal(crypto.Hash(nil), crypto.Hash([]byte{})) {
		t.Errorf("Hash(nil) = %x and Hash of an empty slice = %x", crypto.Hash(nil), crypto.Hash([]byte{}))
	}
	// and a message of exactly HashSize bytes, which no row above is and which is the
	// length RefHash will hand this in task 13. A copy through or an aliasing defect is
	// most natural exactly where the input and the output are the same size, and every
	// row above is short enough for one to hide in. The message is the digest of the
	// empty string and the answer is therefore the published double sha256 of it.
	digestOfEmpty := mustDecodeHex(t, "the digest of the empty message",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	doubleDigest := mustDecodeHex(t, "the double digest of the empty message",
		"5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
	// the probe has to be able to see what it is aimed at: an all zero or palindromic
	// message of that length would make a reversing hash the identity and this row would
	// pass a defect rather than catch it
	assertProbeIsNotItsOwnPermutation(t, "the thirty two byte message", digestOfEmpty)
	if len(digestOfEmpty) != crypto.HashSize() {
		t.Fatalf("the thirty two byte message is %d bytes and HashSize is %d", len(digestOfEmpty), crypto.HashSize())
	}
	for _, suite := range Suites() {
		if got := mustProvider(t, suite).Hash(digestOfEmpty); !bytes.Equal(got, doubleDigest) {
			t.Errorf("suite %#04x Hash of a %d byte message = %x, want %x",
				uint16(suite), len(digestOfEmpty), got, doubleDigest)
		}
	}
}

// A probe over which sorting, reversing, rotating and collapsing to a constant are all
// visible. Every one of those is the identity on some buffer — an ascending one is
// already sorted, a palindromic one already reads backwards, an all zero one is all four
// — and a probe that happens to be one of them turns a test that looks like it catches a
// weakened primitive into a test that cannot. Task 4 shipped a 256 bit key collapsed to
// about 141 bits behind exactly that, so this is asserted before the probe is used.
func assertProbeIsNotItsOwnPermutation(t *testing.T, name string, probe []byte) {
	t.Helper()
	if len(probe) < 2 {
		t.Fatalf("%s is %d bytes, which no permutation can move", name, len(probe))
	}
	ordered := bytes.Clone(probe)
	slices.Sort(ordered)
	if bytes.Equal(probe, ordered) {
		t.Errorf("%s %x is already sorted, so a sorting defect is invisible in it", name, probe)
	}
	slices.Reverse(ordered)
	if bytes.Equal(probe, ordered) {
		t.Errorf("%s %x is sorted descending", name, probe)
	}
	reversed := bytes.Clone(probe)
	slices.Reverse(reversed)
	if bytes.Equal(probe, reversed) {
		t.Errorf("%s %x reads the same backwards, so a reversing defect is invisible in it", name, probe)
	}
	for shift := 1; shift < len(probe); shift++ {
		rotated := append(bytes.Clone(probe[shift:]), probe[:shift]...)
		if bytes.Equal(probe, rotated) {
			t.Errorf("%s %x equals itself rotated by %d", name, probe, shift)
		}
	}
	if bytes.Equal(probe, bytes.Repeat(probe[:1], len(probe))) {
		t.Errorf("%s %x is constant", name, probe)
	}
}

// One RFC 4231 known answer.
type macVector struct {
	name string
	key  []byte
	data []byte
	tag  string
}

// RFC 4231, as crypto/hmac's own table carries it. Case 6's key is longer than the sha256
// block, which is the one input that reaches hmac's key hashing branch: an implementation
// that truncated a long key instead would match every other row here.
func rfc4231Vectors() []macVector {
	return []macVector{
		{
			name: "RFC 4231 test case 1",
			key:  bytes.Repeat([]byte{0x0b}, 20),
			data: []byte("Hi There"),
			tag:  "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		},
		{
			name: "RFC 4231 test case 2",
			key:  []byte("Jefe"),
			data: []byte("what do ya want for nothing?"),
			tag:  "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		},
		{
			name: "RFC 4231 test case 3",
			key:  bytes.Repeat([]byte{0xaa}, 20),
			data: bytes.Repeat([]byte{0xdd}, 50),
			tag:  "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
		},
		{
			name: "RFC 4231 test case 4",
			key:  ascendingBytes(0x01, 25),
			data: bytes.Repeat([]byte{0xcd}, 50),
			tag:  "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
		},
		{
			name: "RFC 4231 test case 6, a key longer than the block",
			key:  bytes.Repeat([]byte{0xaa}, 131),
			data: []byte("Test Using Larger Than Block-Size Key - Hash Key First"),
			tag:  "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
		},
		{
			name: "RFC 4231 test case 7, key and data longer than the block",
			key:  bytes.Repeat([]byte{0xaa}, 131),
			data: []byte("This is a test using a larger than block-size key " +
				"and a larger than block-size data. The key needs to " +
				"be hashed before being used by the HMAC algorithm."),
			tag: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
		},
	}
}

// The run of consecutive byte values the published tables write out in full.
func ascendingBytes(first byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = first + byte(i)
	}
	return b
}

// The published tag is what both Mac and MacVerify are held to. Holding MacVerify to
// Mac's own output instead would be satisfied by a pair that both ignored the key, which
// is the classic mac defect and the one a round trip cannot see.
func TestProviderMacMatchesRfc4231(t *testing.T) {
	for _, vector := range rfc4231Vectors() {
		want := mustDecodeHex(t, vector.name, vector.tag)
		for _, suite := range Suites() {
			crypto := mustProvider(t, suite)
			if got := crypto.Mac(vector.key, vector.data); !bytes.Equal(got, want) {
				t.Errorf("suite %#04x %s: Mac = %x, want %x", uint16(suite), vector.name, got, want)
			}
			if !crypto.MacVerify(vector.key, vector.data, want) {
				t.Errorf("suite %#04x %s: MacVerify rejected the published tag", uint16(suite), vector.name)
			}
		}
	}
}

// The lengths RFC 4231 does not carry, against hmac's own answer rather than against a
// table. HKDF-Extract is HMAC keyed on the salt, and this file already pins the argument
// order that way; the same construction pins the inputs the published table has no row
// for, which is where a substituted default hides.
//
// RFC 4231's shortest key is twenty bytes, its shortest message is eight, and none of its
// rows is thirty two bytes of key — the length every key this package derives will be. So
// a mac that substituted a house key for an absent one, or hashed a key of exactly its own
// digest length first, or read an absent message as some default, agrees with all six
// published rows. Under a substituted default a caller handing no key still gets a tag that
// verifies, and authenticates nobody: the silent downgrade this file exists to refuse.
func TestProviderMacMatchesAnIndependentHmac(t *testing.T) {
	independent := func(key []byte, data []byte) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		return mac.Sum(nil)
	}
	for _, testCase := range []struct {
		name string
		key  []byte
		data []byte
	}{
		{name: "no key at all", key: nil, data: []byte("authenticated data")},
		{name: "an empty key", key: []byte{}, data: []byte("authenticated data")},
		{name: "a key of exactly the digest length", key: bytes.Repeat([]byte{0x0d}, 32), data: []byte("authenticated data")},
		{name: "a key of exactly the block length", key: bytes.Repeat([]byte{0x0d}, 64), data: []byte("authenticated data")},
		{name: "no message at all", key: bytes.Repeat([]byte{0x0d}, 32), data: nil},
		{name: "an empty message", key: bytes.Repeat([]byte{0x0d}, 32), data: []byte{}},
		{name: "neither a key nor a message", key: nil, data: nil},
	} {
		want := independent(testCase.key, testCase.data)
		for _, suite := range Suites() {
			crypto := mustProvider(t, suite)
			if got := crypto.Mac(testCase.key, testCase.data); !bytes.Equal(got, want) {
				t.Errorf("suite %#04x Mac with %s = %x, want %x", uint16(suite), testCase.name, got, want)
			}
			if !crypto.MacVerify(testCase.key, testCase.data, want) {
				t.Errorf("suite %#04x MacVerify with %s rejected hmac's own tag", uint16(suite), testCase.name)
			}
		}
	}
	// and nil and empty are the same absent key and the same absent message, the pair a
	// wrapper telling them apart would answer differently for
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	data := []byte("authenticated data")
	if !bytes.Equal(crypto.Mac(nil, data), crypto.Mac([]byte{}, data)) {
		t.Errorf("Mac reads a nil key and an empty one differently")
	}
	key := bytes.Repeat([]byte{0x0d}, 32)
	if !bytes.Equal(crypto.Mac(key, nil), crypto.Mac(key, []byte{})) {
		t.Errorf("Mac reads a nil message and an empty one differently")
	}
}

// The key has to reach the tag. This is the claim the published table already makes, made
// again over inputs it does not carry, because a mac that hashed only its data agrees
// with nothing published while one that mixed its key in weakly might.
func TestProviderMacDependsOnItsKey(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	data := []byte("authenticated data")
	base := bytes.Repeat([]byte{0x0d}, 32)
	baseTag := crypto.Mac(base, data)
	for _, other := range [][]byte{
		nil,
		{},
		bytes.Repeat([]byte{0x0d}, 31),
		bytes.Repeat([]byte{0x0d}, 33),
		bytes.Repeat([]byte{0x0e}, 32),
		append(bytes.Clone(base[:31]), 0x0c),
		append([]byte{0x0c}, base[1:]...),
	} {
		if got := crypto.Mac(other, data); bytes.Equal(got, baseTag) {
			t.Errorf("Mac under the key %x produced the tag of the key %x", other, base)
		}
		if crypto.MacVerify(other, data, baseTag) {
			t.Errorf("MacVerify accepted a tag made under a different key %x", other)
		}
	}
	for _, other := range [][]byte{nil, {}, []byte("authenticated dat"), []byte("authenticated data!"), []byte("Authenticated data")} {
		if got := crypto.Mac(base, other); bytes.Equal(got, baseTag) {
			t.Errorf("Mac over %q produced the tag of %q", other, data)
		}
	}
}

// Every alteration of the tag, enumerated rather than sampled. A hand written list of
// interesting tags is what this project has understated five times running, and the space
// here is small enough to walk: every single bit of the tag, every truncation, and every
// extension by one byte.
func TestProviderMacVerifyRefusesEveryAlteredTag(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	key := bytes.Repeat([]byte{0x0d}, 32)
	data := []byte("authenticated data")
	tag := crypto.Mac(key, data)
	if !crypto.MacVerify(key, data, tag) {
		t.Fatalf("MacVerify rejected its own tag, so every refusal below means nothing")
	}
	refused := 0
	for i := range tag {
		for bit := 0; bit < 8; bit++ {
			altered := bytes.Clone(tag)
			altered[i] ^= 1 << bit
			if crypto.MacVerify(key, data, altered) {
				t.Errorf("MacVerify accepted a tag with bit %d of byte %d flipped", bit, i)
				continue
			}
			refused++
		}
	}
	if want := 8 * len(tag); refused != want {
		t.Errorf("%d of %d single bit alterations were refused", refused, want)
	}
	for n := 0; n < len(tag); n++ {
		if crypto.MacVerify(key, data, tag[:n]) {
			t.Errorf("MacVerify accepted the first %d bytes of a %d byte tag", n, len(tag))
		}
	}
	for _, extra := range []byte{0x00, 0xff} {
		if crypto.MacVerify(key, data, append(bytes.Clone(tag), extra)) {
			t.Errorf("MacVerify accepted a tag with a trailing %#02x", extra)
		}
	}
	if crypto.MacVerify(key, data, nil) {
		t.Errorf("MacVerify accepted a nil tag")
	}
	if crypto.MacVerify(key, data, make([]byte, len(tag))) {
		t.Errorf("MacVerify accepted an all zero tag")
	}
}

// The file the comparison lives in, and the declaration this gate reads out of it.
const (
	macVerifySourcePath = "crypto.go"
	macVerifySignature  = "func (self *suiteCryptoProvider) MacVerify("
)

// The tokens that make a comparison of secret bytes leak where the first difference is,
// and the one that does not. Guardrail 8 names crypto/subtle.ConstantTimeCompare
// specifically, so the marker is that call rather than merely some constant time function.
var (
	variableTimeComparisons = []string{"bytes.Equal(", "bytes.Compare(", "strings.Compare(", "string(tag)", "string(expected)"}
	constantTimeComparison  = "subtle.ConstantTimeCompare("
)

// One method's body, from its signature to the first line holding nothing but a closing
// brace. Comments are stripped first, so the prose in this file and in crypto.go naming
// bytes.Equal is not what either the gate or its control reads.
func methodBody(t *testing.T, source string, signature string) string {
	t.Helper()
	_, after, found := strings.Cut(codeOf(source), signature)
	if !found {
		t.Fatalf("no declaration of %s", signature)
	}
	body := []string{}
	for _, line := range strings.Split(after, "\n") {
		if line == "}" {
			return strings.Join(body, "\n")
		}
		body = append(body, line)
	}
	t.Fatalf("the declaration of %s is not closed by a line holding only a brace", signature)
	return ""
}

// The comparisons in one body that leak the position of the first differing byte.
func variableTimeComparisonsIn(body string) []string {
	found := []string{}
	for _, token := range variableTimeComparisons {
		if strings.Contains(body, token) {
			found = append(found, token)
		}
	}
	return found
}

// One parsed go file, with the positions its statements can be rendered back through.
//
// Reading the parse tree rather than the file's characters is what turns a token list
// into a shape. A hand written list of banned spellings is the thing this project has
// understated five times running, and a comparison written as control flow carries none
// of the tokens such a list holds while leaking exactly what the ban was about: a plain
// byte loop inserted ahead of a subtle call passes a token gate and returns on the first
// differing byte. A statement list does not care how the leak is spelled.
type parsedSource struct {
	fileSet *token.FileSet
	file    *ast.File
}

// One file of this package, parsed. The path is read at test time rather than embedded,
// so the gate reads what a reviewer will read.
func mustParseSource(t *testing.T, path string) parsedSource {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return mustParseText(t, path, string(source))
}

// The same, over text a control holds, so every matcher below runs on a body known to
// violate the rule as well as on the real one.
func mustParseText(t *testing.T, name string, source string) parsedSource {
	t.Helper()
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, name, source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return parsedSource{fileSet: fileSet, file: file}
}

// The declaration of one function, or of one method on a named receiver type. Absence is
// fatal rather than clean: a gate that stopped finding its subject must fail, not report
// the subject it never read as compliant.
func (self parsedSource) declarationOf(t *testing.T, receiver string, name string) *ast.FuncDecl {
	t.Helper()
	for _, declaration := range self.file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Name.Name != name || self.receiverOf(function) != receiver {
			continue
		}
		if function.Body == nil {
			t.Fatalf("the declaration of %s %s has no body", receiver, name)
		}
		return function
	}
	t.Fatalf("no declaration of %s %s in %s", receiver, name, self.file.Name.Name)
	return nil
}

// The receiver type of a declaration as it is written, or the empty string for a plain
// function.
func (self parsedSource) receiverOf(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) != 1 {
		return ""
	}
	return self.render(function.Recv.List[0].Type)
}

// One node back as source text. Rendering rather than slicing the original bytes is what
// makes an expected statement a constant this file can hold: whitespace and line breaks
// come out canonical however the file was written.
func (self parsedSource) render(node ast.Node) string {
	out := &bytes.Buffer{}
	if err := printer.Fprint(out, self.fileSet, node); err != nil {
		return "!render failed: " + err.Error()
	}
	return out.String()
}

// The statements of one declaration, each rendered.
func (self parsedSource) statementsOf(t *testing.T, receiver string, name string) []string {
	t.Helper()
	rendered := []string{}
	for _, statement := range self.declarationOf(t, receiver, name).Body.List {
		rendered = append(rendered, self.render(statement))
	}
	return rendered
}

// The names of every method on one receiver type declared in this file. What the gates
// below need it for is finding their own subject: a gate told which file to read reports
// a clean bill on a file the implementation has moved out of, which is exactly what
// happened when task 12 put three provider methods in a second file.
func (self parsedSource) methodsOn(receiver string) []string {
	names := []string{}
	for _, declaration := range self.file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || self.receiverOf(function) != receiver {
			continue
		}
		names = append(names, function.Name.Name)
	}
	slices.Sort(names)
	return names
}

// Every call in this file written as a selector on one package, rendered. A gate over
// which constructor a package is entered through reads this rather than the file's
// characters, so a call spelled across two lines or with a differently named import
// still reports as the call it is.
func (self parsedSource) callsToPackage(pkg string) []string {
	calls := []string{}
	ast.Inspect(self.file, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		selector, isSelector := call.Fun.(*ast.SelectorExpr)
		if !isSelector {
			return true
		}
		if base, isIdentifier := selector.X.(*ast.Ident); isIdentifier && base.Name == pkg {
			calls = append(calls, self.render(call))
		}
		return true
	})
	slices.Sort(calls)
	return calls
}

// Every assignment in the file that writes a field of a method's own receiver, as
// "Method: statement". This is the mechanical half of the statelessness claim: a field
// nobody writes is safe to share, and this reports the writes rather than trusting the
// struct to stay the shape it is.
func (self parsedSource) receiverFieldWrites(receiver string) []string {
	writes := []string{}
	for _, declaration := range self.file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Body == nil || self.receiverOf(function) != receiver {
			continue
		}
		names := function.Recv.List[0].Names
		if len(names) != 1 {
			continue
		}
		receiverName := names[0].Name
		ast.Inspect(function.Body, func(node ast.Node) bool {
			targets := []ast.Expr{}
			switch statement := node.(type) {
			case *ast.AssignStmt:
				targets = statement.Lhs
			case *ast.IncDecStmt:
				targets = []ast.Expr{statement.X}
			}
			for _, target := range targets {
				selector, isSelector := target.(*ast.SelectorExpr)
				if !isSelector {
					continue
				}
				base, isIdentifier := selector.X.(*ast.Ident)
				if isIdentifier && base.Name == receiverName {
					writes = append(writes, function.Name.Name+": "+self.render(node))
				}
			}
			return true
		})
	}
	slices.Sort(writes)
	return writes
}

// Guardrail 8, checked by reading the source rather than by measuring, because a timing
// measurement over a 32 byte comparison is noise on this machine and would be a flake in
// continuous integration rather than a gate. What is asserted is therefore exactly what
// was verified: the comparison is the constant time one by inspection, and the inspection
// is mechanical so it survives an edit nobody thinks to rerun it for.
//
// The matcher runs on a control body as well as on the real one. Without that half, a
// matcher that had stopped matching would report the real body clean and pass.
func TestMacVerifyComparesInConstantTime(t *testing.T) {
	source, err := os.ReadFile(macVerifySourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", macVerifySourcePath, err)
	}
	body := methodBody(t, string(source), macVerifySignature)
	if !strings.Contains(body, constantTimeComparison) {
		t.Errorf("the body of MacVerify does not call %s:\n%s", constantTimeComparison, body)
	}
	if found := variableTimeComparisonsIn(body); len(found) != 0 {
		t.Errorf("the body of MacVerify compares with %v", found)
	}
	control := "\texpected := self.Mac(key, data)\n\treturn bytes.Equal(expected, tag)"
	if found := variableTimeComparisonsIn(control); !slices.Equal(found, []string{"bytes.Equal("}) {
		t.Errorf("the matcher reported %v in a body that compares with bytes.Equal", found)
	}
	if strings.Contains(control, constantTimeComparison) {
		t.Errorf("the control body claims to call %s", constantTimeComparison)
	}
}

// The receiver every method of the one implementation hangs off, as it is written.
const providerReceiver = "*suiteCryptoProvider"

// Exactly what MacVerify is allowed to be. The token gate above cannot see a comparison
// spelled as control flow: a plain byte loop inserted ahead of the subtle call leaks the
// position of the first differing byte, carries none of the banned tokens, and still
// contains the required one. So the shape is pinned instead — these three statements and
// nothing else — and a fourth statement of any kind fails here.
var macVerifyStatements = []string{
	"expected := self.Mac(key, data)",
	"if len(tag) != len(expected) {\n\treturn false\n}",
	"return subtle.ConstantTimeCompare(expected, tag) == 1",
}

// A MacVerify that a token gate reports clean and that leaks anyway. Every matcher below
// runs on this as well as on crypto.go, so a matcher that stopped matching fails here
// rather than issuing the real body a clean bill.
const macVerifyLeakingControl = `package mls

func (self *suiteCryptoProvider) MacVerify(key []byte, data []byte, tag []byte) bool {
	expected := self.Mac(key, data)
	if len(tag) != len(expected) {
		return false
	}
	for i := range expected {
		if expected[i] != tag[i] {
			return false
		}
	}
	return subtle.ConstantTimeCompare(expected, tag) == 1
}
`

// Guardrail 8 again, as a shape rather than as a word list. What the token gate above
// asserts is that a named variable time call is absent; what this asserts is that the
// comparison is the only thing in the method, which is the claim the guardrail actually
// makes. The control is a body the token gate passes and this one does not, so the two
// halves are not the same assertion written twice.
func TestMacVerifyIsOnlyTheConstantTimeComparison(t *testing.T) {
	source := mustParseSource(t, macVerifySourcePath)
	got := source.statementsOf(t, providerReceiver, "MacVerify")
	if !slices.Equal(got, macVerifyStatements) {
		t.Errorf("MacVerify is\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(macVerifyStatements, "\n"))
	}
	control := mustParseText(t, "the leaking control", macVerifyLeakingControl)
	leaking := control.statementsOf(t, providerReceiver, "MacVerify")
	if slices.Equal(leaking, macVerifyStatements) {
		t.Errorf("the matcher read a body with a byte loop in it as the shape above")
	}
	// and the control is one the token gate really does pass, or this test is measuring
	// a body the other gate would have caught anyway
	body := methodBody(t, macVerifyLeakingControl, macVerifySignature)
	if !strings.Contains(body, constantTimeComparison) || len(variableTimeComparisonsIn(body)) != 0 {
		t.Errorf("the leaking control does not slip past the token gate, so this shape gate is untested")
	}
}

// One RFC 5869 known answer.
type hkdfVector struct {
	name string
	ikm  []byte
	salt []byte
	prk  string
	info []byte
	okm  string
}

// RFC 5869 appendix A, the sha256 cases, as crypto/hkdf's own table carries them. The
// fourth row is the third with nil where it writes an empty slice: nil and empty are the
// same absent salt, and a wrapper substituting a default for one of them would agree with
// the published answer on only one of the two rows.
func rfc5869Vectors() []hkdfVector {
	return []hkdfVector{
		{
			name: "RFC 5869 test case 1",
			ikm:  bytes.Repeat([]byte{0x0b}, 22),
			salt: ascendingBytes(0x00, 13),
			prk:  "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			info: ascendingBytes(0xf0, 10),
			okm:  "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			name: "RFC 5869 test case 2, inputs longer than the block",
			ikm:  ascendingBytes(0x00, 80),
			salt: ascendingBytes(0x60, 80),
			prk:  "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
			info: ascendingBytes(0xb0, 80),
			okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
				"59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
				"cc30c58179ec3e87c14c01d5c1f3434f1d87",
		},
		{
			name: "RFC 5869 test case 3, empty salt and info",
			ikm:  bytes.Repeat([]byte{0x0b}, 22),
			salt: []byte{},
			prk:  "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			info: []byte{},
			okm:  "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
		{
			name: "RFC 5869 test case 3 with nil where it writes empty",
			ikm:  bytes.Repeat([]byte{0x0b}, 22),
			salt: nil,
			prk:  "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			info: nil,
			okm:  "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
	}
}

// Guardrail 1, against the published pseudorandom keys rather than against this package.
// crypto/hkdf.Extract is (ikm, salt) and every spec text in this project writes
// HKDF-Extract(salt, ikm); the two are distinguishable only by a value neither side of
// the swap invented, which is what RFC 5869 prints.
func TestProviderExtractMatchesRfc5869(t *testing.T) {
	for _, vector := range rfc5869Vectors() {
		want := mustDecodeHex(t, vector.name, vector.prk)
		for _, suite := range Suites() {
			crypto := mustProvider(t, suite)
			if got := crypto.Extract(vector.salt, vector.ikm); !bytes.Equal(got, want) {
				t.Errorf("suite %#04x %s: Extract(salt, ikm) = %x, want %x — the arguments are swapped",
					uint16(suite), vector.name, got, want)
			}
			if len(vector.salt) == 0 || bytes.Equal(vector.salt, vector.ikm) {
				continue
			}
			if got := crypto.Extract(vector.ikm, vector.salt); bytes.Equal(got, want) {
				t.Errorf("suite %#04x %s: Extract is symmetric in salt and ikm, which is impossible for hmac",
					uint16(suite), vector.name)
			}
		}
	}
}

// The same claim by an independent construction rather than by a table: HKDF-Extract is
// literally HMAC keyed on the salt over the input keying material, so a reader holding
// crypto/hmac can check the order without a vector at all.
func TestProviderExtractArgumentOrder(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	salt := []byte("this is the salt")
	ikm := []byte("this is the input keying material")

	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	want := mac.Sum(nil)

	if got := crypto.Extract(salt, ikm); !bytes.Equal(got, want) {
		t.Fatalf("Extract(salt, ikm) = %x, want %x — the arguments are swapped", got, want)
	}
	if got := crypto.Extract(ikm, salt); bytes.Equal(got, want) {
		t.Fatalf("Extract is symmetric, which is impossible for hmac")
	}
}

// Expand against the published output keying material, at the published lengths. The
// lengths matter as much as the bytes: case 2 asks for 82, which is three sha256 blocks,
// so a counter that restarted or that stopped after one block fails here and passes every
// fixed 32 byte derivation this package otherwise performs.
func TestProviderExpandMatchesRfc5869(t *testing.T) {
	for _, vector := range rfc5869Vectors() {
		prk := mustDecodeHex(t, vector.name+" prk", vector.prk)
		want := mustDecodeHex(t, vector.name+" okm", vector.okm)
		for _, suite := range Suites() {
			crypto := mustProvider(t, suite)
			if got := crypto.Expand(prk, vector.info, len(want)); !bytes.Equal(got, want) {
				t.Errorf("suite %#04x %s: Expand = %x, want %x", uint16(suite), vector.name, got, want)
			}
		}
	}
}

// The property separating HKDF-Expand from a wrapper that folded the length into the
// info: the output for a short length is a prefix of the output for a long one. The
// labelled expand in hpke.go deliberately does not have it, so calling that one here
// would fail this and nothing else in this file.
func TestProviderExpandIsAPrefixStream(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	prk := crypto.Extract([]byte("salt"), []byte("ikm"))
	long := crypto.Expand(prk, []byte("info"), 200)
	for _, length := range []int{0, 1, 16, 32, 33, 64, 199, 200} {
		got := crypto.Expand(prk, []byte("info"), length)
		if len(got) != length {
			t.Errorf("Expand asked for %d bytes returned %d", length, len(got))
			continue
		}
		if !bytes.Equal(got, long[:length]) {
			t.Errorf("Expand at %d = %x, want the first %d bytes of %x", length, got, length, long)
		}
	}
	if bytes.Equal(crypto.Expand(prk, []byte("info"), 32), crypto.Expand(prk, []byte("other"), 32)) {
		t.Errorf("Expand ignores its info")
	}
	if bytes.Equal(crypto.Expand(prk, nil, 32), crypto.Expand(prk, []byte{0x00}, 32)) {
		t.Errorf("Expand reads an empty info and a single zero byte alike, so the conversion to string is not byte preserving")
	}
	if !bytes.Equal(crypto.Expand(prk, nil, 32), crypto.Expand(prk, []byte{}, 32)) {
		t.Errorf("Expand distinguishes a nil info from an empty one")
	}
	if bytes.Equal(crypto.Expand(prk, []byte("info"), 32), crypto.Expand(crypto.Extract([]byte("other salt"), []byte("ikm")), []byte("info"), 32)) {
		t.Errorf("Expand ignores its pseudorandom key")
	}
	// every prk above is exactly the hash length, which is the one a wrapper truncating
	// or padding its key agrees with. A longer one has to reach the hmac whole
	long64 := append(bytes.Clone(prk), crypto.Extract([]byte("second salt"), []byte("ikm"))...)
	if bytes.Equal(crypto.Expand(long64, []byte("info"), 32), crypto.Expand(long64[:32], []byte("info"), 32)) {
		t.Errorf("Expand truncates a pseudorandom key longer than the hash")
	}
	if bytes.Equal(crypto.Expand(long64, []byte("info"), 32), crypto.Expand(long64[32:], []byte("info"), 32)) {
		t.Errorf("Expand reads only the tail of a pseudorandom key longer than the hash")
	}
}

// The other end of the same refusal. RFC 5869 section 2.3 requires a pseudorandom key of
// at least the hash length, crypto/hkdf checks it only in fips140-only mode, and expanding
// from a shorter one hands back every byte that was asked for while deriving all of them
// from less entropy than the suite claims. That is the same silent downgrade as a short
// return arriving from the other side, and a caller passing a stub or an empty slice is
// exactly how it arrives.
func TestProviderExpandRefusesAShortPseudorandomKey(t *testing.T) {
	for _, suite := range Suites() {
		crypto := mustProvider(t, suite)
		full := crypto.Extract([]byte("salt"), []byte("ikm"))
		if len(full) != crypto.HashSize() {
			t.Fatalf("suite %#04x Extract produced %d bytes for a HashSize of %d", uint16(suite), len(full), crypto.HashSize())
		}
		for _, short := range [][]byte{nil, {}, full[:1], full[:16], full[:crypto.HashSize()-1]} {
			recovered := recoveredPanic(func() { crypto.Expand(short, []byte("info"), 32) })
			if recovered == nil {
				t.Errorf("suite %#04x Expand under a %d byte pseudorandom key returned instead of refusing",
					uint16(suite), len(short))
				continue
			}
			if got := fmt.Sprint(recovered); !strings.HasPrefix(got, "mls: hkdf expand pseudorandom key ") {
				t.Errorf("suite %#04x Expand under a %d byte pseudorandom key was refused by %q, not by this package's gate",
					uint16(suite), len(short), got)
			}
		}
		// the control: a key of exactly the hash length, and one longer, are both served,
		// or the table above is satisfied by an Expand that refuses everything
		for _, served := range [][]byte{full, append(bytes.Clone(full), full...)} {
			if recovered := recoveredPanic(func() { crypto.Expand(served, []byte("info"), 32) }); recovered != nil {
				t.Errorf("suite %#04x Expand under a %d byte pseudorandom key was refused with %v",
					uint16(suite), len(served), recovered)
			}
		}
	}
}

// The boundary, at the library's own ceiling rather than at a constant of this package's
// choosing. hpkeMaxExpandLength is 255*Nh and TestHpkeExpandCeilingIsTheLibrarysOwnBoundary
// already pins it against crypto/hkdf itself, so what is left here is that this wrapper
// refuses the same lengths and serves the same ones — a gate one off in either direction
// either kills the process on a length the library serves or serves one it does not.
func TestProviderExpandRefusesUnrepresentableLengths(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	prk := crypto.Extract([]byte("salt"), []byte("ikm"))
	for _, length := range []int{0, 1, 32, hpkeMaxExpandLength - 1, hpkeMaxExpandLength} {
		if got := len(crypto.Expand(prk, []byte("info"), length)); got != length {
			t.Errorf("Expand asked for %d bytes returned %d", length, got)
		}
	}
	for _, length := range []int{-1, -32, hpkeMaxExpandLength + 1, 1 << 16} {
		recovered := recoveredPanic(func() { crypto.Expand(prk, []byte("info"), length) })
		if recovered == nil {
			t.Errorf("Expand returned for a length of %d instead of refusing it", length)
			continue
		}
		// and the refusal is this package's gate rather than a makeslice from inside
		// the kdf, which is what a negative length reaches when the gate is not there
		if got := fmt.Sprint(recovered); !strings.HasPrefix(got, "mls: hkdf expand length ") {
			t.Errorf("Expand at a length of %d was refused by %q, not by this package's gate", length, got)
		}
	}
}

// The lengths the ciphersuite fixes, refused for both suites and in both directions. The
// key gate is the one that has to read the registry: 16 bytes is a whole key under 0x0001
// and a short one under 0x0003, so a gate written against a literal passes one suite.
func TestProviderAeadRejectsWrongSizes(t *testing.T) {
	for _, suite := range Suites() {
		crypto := mustProvider(t, suite)
		key := make([]byte, crypto.KeySize())
		nonce := make([]byte, crypto.NonceSize())
		for _, wrong := range [][]byte{nil, {}, key[:len(key)-1], append(bytes.Clone(key), 0x00), make([]byte, 16), make([]byte, 32)} {
			if len(wrong) == crypto.KeySize() {
				continue
			}
			if _, err := crypto.AeadSeal(wrong, nonce, nil, nil); !errors.Is(err, ErrBadKeyLength) {
				t.Errorf("suite %#04x seal under a %d byte key error = %v, want ErrBadKeyLength", uint16(suite), len(wrong), err)
			}
			if _, err := crypto.AeadOpen(wrong, nonce, nil, make([]byte, 16)); !errors.Is(err, ErrBadKeyLength) {
				t.Errorf("suite %#04x open under a %d byte key error = %v, want ErrBadKeyLength", uint16(suite), len(wrong), err)
			}
		}
		for _, wrong := range [][]byte{nil, {}, nonce[:len(nonce)-1], append(bytes.Clone(nonce), 0x00), make([]byte, 8), make([]byte, 24)} {
			if _, err := crypto.AeadSeal(key, wrong, nil, nil); !errors.Is(err, ErrBadNonceLength) {
				t.Errorf("suite %#04x seal under a %d byte nonce error = %v, want ErrBadNonceLength", uint16(suite), len(wrong), err)
			}
			if _, err := crypto.AeadOpen(key, wrong, nil, make([]byte, 16)); !errors.Is(err, ErrBadNonceLength) {
				t.Errorf("suite %#04x open under a %d byte nonce error = %v, want ErrBadNonceLength", uint16(suite), len(wrong), err)
			}
		}
		ciphertext, err := crypto.AeadSeal(key, nonce, []byte("aad"), []byte("plaintext"))
		if err != nil {
			t.Fatalf("suite %#04x seal: %v", uint16(suite), err)
		}
		if _, err := crypto.AeadOpen(key, nonce, []byte("other aad"), ciphertext); !errors.Is(err, ErrAeadOpen) {
			t.Errorf("suite %#04x open under the wrong aad error = %v, want ErrAeadOpen", uint16(suite), err)
		}
		back, err := crypto.AeadOpen(key, nonce, []byte("aad"), ciphertext)
		if err != nil {
			t.Fatalf("suite %#04x open: %v", uint16(suite), err)
		}
		if !bytes.Equal(back, []byte("plaintext")) {
			t.Fatalf("suite %#04x open returned %q", uint16(suite), back)
		}
	}
}

// The aead against the vendored RFC 9180 corpus, through the provider rather than through
// the hpke context. Two things are pinned that suite.go alone cannot pin: the published
// key is exactly KeySize bytes and the published nonce exactly NonceSize, so a size that
// disagreed with the ciphersuite is refused by AeadSeal's own length gate rather than
// merely disagreeing with a table this repository wrote for itself.
func TestProviderAeadMatchesThePublishedEncryptions(t *testing.T) {
	sealed := 0
	for _, vector := range loadHpkeVectors(t) {
		crypto := mustProvider(t, vector.suite)
		key := decodeVectorField(t, vector.name, "key", vector.Key)
		if len(key) != crypto.KeySize() {
			t.Errorf("%s: the published key is %d bytes and KeySize is %d", vector.name, len(key), crypto.KeySize())
		}
		for _, encryption := range vector.Encryptions {
			nonce := decodeVectorField(t, vector.name, "nonce", encryption.Nonce)
			aad := decodeVectorField(t, vector.name, "aad", encryption.Aad)
			plaintext := decodeVectorField(t, vector.name, "pt", encryption.Pt)
			want := decodeVectorField(t, vector.name, "ct", encryption.Ct)
			if len(nonce) != crypto.NonceSize() {
				t.Fatalf("%s: the published nonce is %d bytes and NonceSize is %d", vector.name, len(nonce), crypto.NonceSize())
			}
			ciphertext, err := crypto.AeadSeal(key, nonce, aad, plaintext)
			if err != nil {
				t.Fatalf("%s: seal at sequence %d: %v", vector.name, encryption.sequence, err)
			}
			if !bytes.Equal(ciphertext, want) {
				t.Errorf("%s: ciphertext at sequence %d = %x, want %x", vector.name, encryption.sequence, ciphertext, want)
			}
			back, err := crypto.AeadOpen(key, nonce, aad, want)
			if err != nil {
				t.Fatalf("%s: open at sequence %d: %v", vector.name, encryption.sequence, err)
			}
			if !bytes.Equal(back, plaintext) {
				t.Errorf("%s: open at sequence %d returned %x, want %x", vector.name, encryption.sequence, back, plaintext)
			}
			sealed++
		}
	}
	if sealed == 0 {
		t.Fatal("no published encryption was sealed, so this known answer asserted nothing")
	}
	t.Logf("%d published encryptions sealed and opened through the provider", sealed)
}

// The empty plaintext, which is the input that makes a successful open and a refusal look
// alike. When the plaintext is empty the ciphertext is exactly a tag and the plaintext
// that comes back is a nil slice, so the only thing separating an authentic empty message
// from a forged one is the error — and an implementation that swallowed it would return
// the same nil, nil for both. That is the total authentication bypass p2 task 10 shipped
// behind a test that carried this very input and then never altered it, so here every
// single bit of the tag is altered.
func TestProviderAeadOpenRefusesAForgedEmptyMessage(t *testing.T) {
	for _, suite := range Suites() {
		crypto := mustProvider(t, suite)
		params, err := LookupSuite(suite)
		if err != nil {
			t.Fatalf("LookupSuite(%#04x): %v", uint16(suite), err)
		}
		key := bytes.Repeat([]byte{0x11}, crypto.KeySize())
		nonce := bytes.Repeat([]byte{0x22}, crypto.NonceSize())
		aad := []byte("aad")
		ciphertext, err := crypto.AeadSeal(key, nonce, aad, nil)
		if err != nil {
			t.Fatalf("suite %#04x seal of an empty plaintext: %v", uint16(suite), err)
		}
		if len(ciphertext) != params.Nt {
			t.Fatalf("suite %#04x sealed an empty plaintext into %d bytes, want a bare %d byte tag", uint16(suite), len(ciphertext), params.Nt)
		}
		back, err := crypto.AeadOpen(key, nonce, aad, ciphertext)
		if err != nil {
			t.Fatalf("suite %#04x open of an authentic empty message: %v", uint16(suite), err)
		}
		if len(back) != 0 {
			t.Fatalf("suite %#04x open of an empty message returned %x", uint16(suite), back)
		}
		refused := 0
		for i := range ciphertext {
			for bit := 0; bit < 8; bit++ {
				forged := bytes.Clone(ciphertext)
				forged[i] ^= 1 << bit
				plaintext, err := crypto.AeadOpen(key, nonce, aad, forged)
				if !errors.Is(err, ErrAeadOpen) {
					t.Errorf("suite %#04x open of a tag with bit %d of byte %d flipped = %v, want ErrAeadOpen", uint16(suite), bit, i, err)
					continue
				}
				if plaintext != nil {
					t.Errorf("suite %#04x open returned %d bytes alongside %v", uint16(suite), len(plaintext), err)
					continue
				}
				refused++
			}
		}
		if want := 8 * len(ciphertext); refused != want {
			t.Errorf("suite %#04x refused %d of %d forged empty messages", uint16(suite), refused, want)
		}
		for _, forged := range [][]byte{nil, {}, make([]byte, params.Nt-1), make([]byte, params.Nt), make([]byte, params.Nt+1), bytes.Repeat([]byte{0xff}, params.Nt)} {
			if plaintext, err := crypto.AeadOpen(key, nonce, aad, forged); !errors.Is(err, ErrAeadOpen) || plaintext != nil {
				t.Errorf("suite %#04x open of a %d byte forgery = %x, %v, want nil and ErrAeadOpen", uint16(suite), len(forged), plaintext, err)
			}
		}
		for _, wrongAad := range [][]byte{nil, {}, []byte("aa"), []byte("aad!"), []byte("AAD")} {
			if _, err := crypto.AeadOpen(key, nonce, wrongAad, ciphertext); !errors.Is(err, ErrAeadOpen) {
				t.Errorf("suite %#04x open of an empty message under the aad %q = %v, want ErrAeadOpen", uint16(suite), wrongAad, err)
			}
		}
		otherKey := bytes.Clone(key)
		otherKey[0] ^= 0x01
		if _, err := crypto.AeadOpen(otherKey, nonce, aad, ciphertext); !errors.Is(err, ErrAeadOpen) {
			t.Errorf("suite %#04x open of an empty message under another key = %v, want ErrAeadOpen", uint16(suite), err)
		}
		otherNonce := bytes.Clone(nonce)
		otherNonce[0] ^= 0x01
		if _, err := crypto.AeadOpen(key, otherNonce, aad, ciphertext); !errors.Is(err, ErrAeadOpen) {
			t.Errorf("suite %#04x open of an empty message under another nonce = %v, want ErrAeadOpen", uint16(suite), err)
		}
	}
}

// Nothing the provider returns may share memory with what it was handed, and nothing it
// was handed may come back changed. The aead is where this bites: cipher.AEAD documents
// that its destination may overlap its input exactly, so sealing into plaintext[:0] and
// opening into ciphertext[:0] both compile and both round trip while destroying a
// caller's buffer — and a caller that reuses a plaintext across two recipients then
// encrypts rubbish to the second.
func TestProviderResultsDoNotShareMemoryWithTheirInputs(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	spare := func(b []byte) []byte { return append(make([]byte, 0, len(b)+64), b...) }

	// both at a length nothing here shares with a result and at exactly HashSize, where
	// the natural mistake is to hand the caller's own buffer back
	for _, data := range [][]byte{
		spare([]byte("the message")),
		spare(crypto.Hash([]byte("a message of exactly the digest length"))),
	} {
		dataBefore := bytes.Clone(data)
		digest := crypto.Hash(data)
		tag := crypto.Mac(spare([]byte("key")), data)
		prk := crypto.Extract(spare([]byte("salt")), data)
		okm := crypto.Expand(prk, data, 48)
		if !bytes.Equal(data, dataBefore) {
			t.Errorf("a primitive changed its %d byte input from %x to %x", len(data), dataBefore, data)
		}
		for _, result := range [][]byte{digest, tag, prk, okm} {
			if len(result) != 0 && &result[0] == &data[0] {
				t.Errorf("a primitive returned a slice aliasing its %d byte input", len(data))
			}
		}
	}

	key := spare(bytes.Repeat([]byte{0x33}, crypto.KeySize()))
	nonce := spare(bytes.Repeat([]byte{0x44}, crypto.NonceSize()))
	aad := spare([]byte("aad"))
	plaintext := spare([]byte("plaintext that is long enough to notice"))
	keyBefore, nonceBefore := bytes.Clone(key), bytes.Clone(nonce)
	aadBefore, plaintextBefore := bytes.Clone(aad), bytes.Clone(plaintext)
	ciphertext, err := crypto.AeadSeal(key, nonce, aad, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !bytes.Equal(plaintext, plaintextBefore) {
		t.Errorf("seal changed its plaintext from %x to %x", plaintextBefore, plaintext)
	}
	if !bytes.Equal(aad, aadBefore) || !bytes.Equal(key, keyBefore) || !bytes.Equal(nonce, nonceBefore) {
		t.Errorf("seal changed one of its key, nonce or aad")
	}
	for i := range ciphertext {
		ciphertext[i] ^= 0xff
	}
	if !bytes.Equal(plaintext, plaintextBefore) {
		t.Errorf("the sealed ciphertext shares memory with the plaintext")
	}
	for i := range ciphertext {
		ciphertext[i] ^= 0xff
	}
	ciphertextBefore := bytes.Clone(ciphertext)
	back, err := crypto.AeadOpen(key, nonce, aad, ciphertext)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(ciphertext, ciphertextBefore) {
		t.Errorf("open changed its ciphertext from %x to %x", ciphertextBefore, ciphertext)
	}
	if len(back) != 0 && &back[0] == &ciphertext[0] {
		t.Errorf("open returned a plaintext aliasing the ciphertext")
	}
	assertEveryProviderCallLeavesItsArgumentsAlone(t, crypto)
}

// The same claim over every method of the interface that takes bytes, mechanically.
//
// Two things separate this from the hand written half above. It covers the whole surface
// and says so, so a method added later is not silently left out. And every argument is
// cut from a longer array and compared over the whole array afterwards: a provider that
// appends into a caller's spare capacity to save an allocation leaves len alone, so a
// comparison that stops at len reports nothing while the caller's next read past len
// comes back changed.
func assertEveryProviderCallLeavesItsArgumentsAlone(t *testing.T, crypto CryptoProvider) {
	t.Helper()
	secret := bytes.Repeat([]byte{0x61}, crypto.HashSize())
	message := []byte("a message the provider is handed rather than one it makes")
	tag := crypto.Mac(secret, message)
	key := bytes.Repeat([]byte{0x62}, crypto.KeySize())
	nonce := bytes.Repeat([]byte{0x63}, crypto.NonceSize())
	aad := []byte("aad")
	sealed, err := crypto.AeadSeal(key, nonce, aad, message)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	signaturePriv, signaturePub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("generate the key pair the signature rows are built over: %v", err)
	}
	signature, err := crypto.SignWithLabel(signaturePriv, "label", message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	covered := []string{}
	for _, testCase := range []struct {
		name string
		call func(take func(content []byte) []byte) []byte
	}{
		{name: "Hash", call: func(take func([]byte) []byte) []byte { return crypto.Hash(take(message)) }},
		{name: "Mac", call: func(take func([]byte) []byte) []byte { return crypto.Mac(take(secret), take(message)) }},
		{name: "MacVerify", call: func(take func([]byte) []byte) []byte {
			if !crypto.MacVerify(take(secret), take(message), take(tag)) {
				t.Errorf("MacVerify refused a tag it had just produced, so this ran the refusal path")
			}
			return nil
		}},
		{name: "Extract", call: func(take func([]byte) []byte) []byte { return crypto.Extract(take(secret), take(message)) }},
		{name: "Expand", call: func(take func([]byte) []byte) []byte { return crypto.Expand(take(secret), take(message), 48) }},
		{name: "ExpandWithLabel", call: func(take func([]byte) []byte) []byte {
			return crypto.ExpandWithLabel(take(secret), "label", take(message), 48)
		}},
		{name: "DeriveSecret", call: func(take func([]byte) []byte) []byte {
			return crypto.DeriveSecret(take(secret), "label")
		}},
		{name: "DeriveTreeSecret", call: func(take func([]byte) []byte) []byte {
			return crypto.DeriveTreeSecret(take(secret), "label", 7, 48)
		}},
		{name: "AeadSeal", call: func(take func([]byte) []byte) []byte {
			ciphertext, err := crypto.AeadSeal(take(key), take(nonce), take(aad), take(message))
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			return ciphertext
		}},
		{name: "AeadOpen", call: func(take func([]byte) []byte) []byte {
			plaintext, err := crypto.AeadOpen(take(key), take(nonce), take(aad), take(sealed))
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			return plaintext
		}},
		{name: "SignWithLabel", call: func(take func([]byte) []byte) []byte {
			produced, err := crypto.SignWithLabel(SignaturePrivateKey(take(signaturePriv)), "label", take(message))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			return produced
		}},
		{name: "VerifyWithLabel", call: func(take func([]byte) []byte) []byte {
			if err := crypto.VerifyWithLabel(SignaturePublicKey(take(signaturePub)), "label",
				take(message), take(signature)); err != nil {
				t.Errorf("VerifyWithLabel refused a signature it had just made, so this ran the refusal path")
			}
			return nil
		}},
	} {
		covered = append(covered, testCase.name)
		recorder := &argumentRecorder{}
		result := testCase.call(recorder.take)
		if len(recorder.arrays) == 0 {
			t.Errorf("%s was handed nothing, so this row observed nothing", testCase.name)
			continue
		}
		if changed := recorder.changed(); len(changed) != 0 {
			t.Errorf("%s changed the storage behind arguments %v of the %d it was handed",
				testCase.name, changed, len(recorder.arrays))
		}
		if recorder.aliases(result) {
			t.Errorf("%s returned a slice over one of its arguments", testCase.name)
		}
	}
	assertCoversTheProviderSurface(t, "the argument immutability table", covered, map[string]string{
		"Random":           "is handed no bytes, only a count",
		"SignatureKeyPair": "is handed no bytes, only its provider's own reader",
	})
}

// The arguments one provider call was handed, and the storage behind each of them.
//
// Every argument is cut from an array longer than itself, so len(argument) is strictly
// less than cap(argument) and an append into the spare capacity is a write this can see.
// Recording the array rather than the slice is the whole point: the caller's slice header
// never moves, and the bytes past its length are the ones a defect writes into.
type argumentRecorder struct {
	arrays [][]byte
	before [][]byte
}

// One argument, over storage this recorder keeps a copy of. The trailing bytes are a
// pattern rather than zeros: a mutant that appended a zero into the spare capacity would
// be invisible against an array that was already zero there.
func (self *argumentRecorder) take(content []byte) []byte {
	array := append(bytes.Clone(content), bytes.Repeat([]byte{0x5c, 0xa3}, 32)...)
	self.arrays = append(self.arrays, array)
	self.before = append(self.before, bytes.Clone(array))
	return array[:len(content)]
}

// The indexes of the arguments whose storage came back changed.
func (self *argumentRecorder) changed() []int {
	changed := []int{}
	for i, array := range self.arrays {
		if !bytes.Equal(array, self.before[i]) {
			changed = append(changed, i)
		}
	}
	return changed
}

// Whether a result is cut from the storage behind any argument. Comparing the result's
// first element against every byte of every argument rather than against the first byte
// of each catches a result taken from the middle of a caller's buffer as well as one
// taken from the front.
func (self *argumentRecorder) aliases(result []byte) bool {
	if len(result) == 0 {
		return false
	}
	for _, array := range self.arrays {
		for i := range array {
			if &array[i] == &result[0] {
				return true
			}
		}
	}
	return false
}

// The bytes the scripted reader hands out. Ninety six of them, in windows a mutant has to
// tell apart, so a Random that restarted at the beginning is as visible as one that drew
// more than it returned.
const randomScriptHex = "3f7a01d92c58be04ff1e6b83a7409dcc5210748fe6b3915da0c2ef47368b1da9" +
	"0e94c3f6725ab8d1490fe72c86b35a0d1fc6e849b27d305aef16942c7b8a5d30" +
	"b6027fd4e95c1a83407bcf29d81e63a5f0349d7c2be851a6c4907f3d5eb218ca"

func randomScript(t *testing.T) []byte {
	t.Helper()
	return mustDecodeHex(t, "the random script", randomScriptHex)
}

// The lengths drawn from the script, in order, and the one place they are written. The
// adequacy test and the consumption test both read this, so the windows proved adequate
// are exactly the windows drawn: a list written out twice drifts, and a probe proved over
// bytes nothing asks for proves nothing.
var randomDrawLengths = []int{32, 16, 1, 47}

// The stretches of the script the draws above land in, plus the whole of it. A draw of one
// byte contributes no window: sorting, reversing and rotating a single byte are all the
// identity, so there is nothing to prove about it and claiming otherwise would fail.
func randomScriptWindows(t *testing.T) [][]byte {
	t.Helper()
	script := randomScript(t)
	windows := [][]byte{script}
	taken := 0
	for _, length := range randomDrawLengths {
		if length > 1 {
			windows = append(windows, script[taken:taken+length])
		}
		taken += length
	}
	if taken != len(script) {
		t.Fatalf("the draws cover %d bytes of a %d byte script", taken, len(script))
	}
	return windows
}

// The probe has to be able to see the mutants it is aimed at, and an ascending or
// palindromic script cannot: sorting a script that is already sorted is the identity, and
// so is reversing one that reads the same backwards. Task 4's key generator passed a
// reversed, a rotated and a sorted scalar because its test fed a constant reader, where
// all three are the identity — so the adequacy of this script is asserted before anything
// is asserted with it.
func TestRandomScriptCanSeeAWeakenedReader(t *testing.T) {
	script := randomScript(t)
	if len(script) != 96 {
		t.Fatalf("the script is %d bytes, want 96", len(script))
	}
	windows := randomScriptWindows(t)
	for i, window := range windows {
		assertProbeIsNotItsOwnPermutation(t, fmt.Sprintf("the window %d of the script", i), window)
	}
	for i := 0; i < len(windows); i++ {
		for j := i + 1; j < len(windows); j++ {
			if len(windows[i]) == len(windows[j]) && bytes.Equal(windows[i], windows[j]) {
				t.Errorf("two windows of the script are equal, so a reader that restarted would be invisible")
			}
		}
	}
}

// Random must hand back the bytes it was offered, in order, and consume exactly as many
// as it returns. Each of those three is a separate mutant — a reader that is ignored, a
// reader whose bytes are permuted, and a reader that is over drawn so the next call starts
// in the wrong place — and none of them is visible to a test that only asks whether the
// result is non zero and changes between calls.
func TestProviderRandomConsumesItsReaderInOrder(t *testing.T) {
	script := randomScript(t)
	crypto := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, bytes.NewReader(script))
	taken := 0
	for _, length := range randomDrawLengths {
		got := crypto.Random(length)
		want := script[taken : taken+length]
		if !bytes.Equal(got, want) {
			t.Fatalf("Random(%d) after %d bytes = %x, want %x", length, taken, got, want)
		}
		taken += length
	}
	if taken != len(script) {
		t.Fatalf("the script is %d bytes and the calls asked for %d", len(script), taken)
	}
	// and the reader is empty now, which is what says nothing beyond each request was
	// drawn from it along the way
	if recovered := recoveredPanic(func() { crypto.Random(1) }); recovered == nil {
		t.Fatalf("Random returned a byte the script did not hold")
	}
}

// A reader that hands back one byte at a time, and stalls a few times first. Both are
// legal io.Reader behaviour, and a bare Read would leave every byte after the first as the
// zero it was allocated with — the silently weak value this whole file is about.
type dribblingReader struct {
	remaining []byte
	stalls    int
}

func (self *dribblingReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if self.stalls > 0 {
		self.stalls--
		return 0, nil
	}
	if len(self.remaining) == 0 {
		return 0, io.EOF
	}
	p[0] = self.remaining[0]
	self.remaining = self.remaining[1:]
	return 1, nil
}

func TestProviderRandomAssemblesAPartialReader(t *testing.T) {
	script := randomScript(t)
	reader := &dribblingReader{remaining: bytes.Clone(script), stalls: 3}
	crypto := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, reader)
	if got := crypto.Random(len(script)); !bytes.Equal(got, script) {
		t.Fatalf("Random over a one byte at a time reader = %x, want %x", got, script)
	}
}

// A short or failing source must not yield short or zero key material. Random has no
// error return in the interface spec A section 3.3 fixes, so the only refusal available
// is a panic, and it is asserted rather than assumed — the alternative is a caller
// deriving a key from a tail of zeroes and reporting success.
func TestProviderRandomRefusesAShortOrFailingReader(t *testing.T) {
	script := randomScript(t)
	for _, testCase := range []struct {
		name   string
		reader io.Reader
	}{
		{name: "an exhausted reader", reader: bytes.NewReader(nil)},
		{name: "a reader one byte short", reader: bytes.NewReader(script[:31])},
		{name: "a reader that fails at once", reader: failingReader{err: errors.New("entropy source is down")}},
		{name: "a reader that stalls then ends", reader: &dribblingReader{remaining: bytes.Clone(script[:7]), stalls: 2}},
	} {
		crypto := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, testCase.reader)
		if recovered := recoveredPanic(func() { crypto.Random(32) }); recovered == nil {
			t.Errorf("Random over %s returned instead of refusing", testCase.name)
		}
	}
	// the control: a reader with enough bytes must not be refused, or the table above is
	// satisfied by a Random that refuses everything
	crypto := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, bytes.NewReader(script))
	if recovered := recoveredPanic(func() { crypto.Random(32) }); recovered != nil {
		t.Errorf("Random over a sufficient reader was refused with %v", recovered)
	}
}

func TestProviderRandomLengths(t *testing.T) {
	script := randomScript(t)
	crypto := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, bytes.NewReader(script))
	// a request for nothing draws nothing, so the next request still starts at the top
	if got := crypto.Random(0); len(got) != 0 {
		t.Errorf("Random(0) returned %x", got)
	}
	if got := crypto.Random(4); !bytes.Equal(got, script[:4]) {
		t.Errorf("after Random(0) the next four bytes were %x, want %x", got, script[:4])
	}
	if recovered := recoveredPanic(func() { crypto.Random(-1) }); recovered == nil {
		t.Errorf("Random(-1) returned instead of refusing")
	}
}

func TestProviderRandomIsNotConstant(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	first := crypto.Random(32)
	if len(first) != 32 {
		t.Fatalf("Random(32) returned %d bytes", len(first))
	}
	if bytes.Equal(first, make([]byte, 32)) {
		t.Fatalf("Random returned all zeroes")
	}
	if bytes.Equal(first, crypto.Random(32)) {
		t.Fatalf("Random repeated itself")
	}
}

// Two default providers must not repeat each other. This is named for what it can see
// rather than for the property it is near: a stream that varies is all a caller outside
// the process can observe, and a sha256 counter, a linear congruential generator and a
// process wide seed all vary. The claim that the varying stream is the operating system's
// is not observable from here at all — no black box test separates a cryptographic source
// from a seeded one, which is the whole point of a seeded one — so it is held by reading
// the constructor instead, in TestNewCryptoProviderReadsTheProcessEntropySource below.
// What this catches is the degenerate half: a constant or zero stream.
func TestTwoDefaultProvidersDoNotRepeatEachOther(t *testing.T) {
	first := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	second := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	if bytes.Equal(first.Random(32), second.Random(32)) {
		t.Fatalf("two default providers produced the same random bytes")
	}
}

// Exactly what NewCryptoProvider is allowed to be. One statement, naming crypto/rand's
// own reader and constructing nothing: a wrapper around it, a seeded expansion of it or
// any other reader is a different statement and fails.
var newCryptoProviderStatements = []string{
	"return NewCryptoProviderWithRandom(suite, rand.Reader)",
}

// The import that supplies it, asserted separately so a file that no longer reads the
// operating system at all fails on the import as well as on the statement.
const cryptoRandImportPath = `"crypto/rand"`

// A constructor over a stream that varies and is entirely predictable. Deleting
// crypto/rand from crypto.go and substituting this passes every behavioural test in this
// package, because two providers over a counter still disagree with each other — so this
// is the body every matcher below is proved against.
const newCryptoProviderDeterministicControl = `package mls

import (
	"crypto/sha256"
)

func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error) {
	return NewCryptoProviderWithRandom(suite, deterministicDefault{})
}

type deterministicDefault struct{}

var deterministicCounter uint64

func (deterministicDefault) Read(p []byte) (int, error) {
	deterministicCounter++
	block := sha256.Sum256([]byte{byte(deterministicCounter)})
	return copy(p, block[:]), nil
}
`

// The source of every key this package will ever generate, held by reading crypto.go.
//
// This is the one claim in this file that no input can distinguish from its violation.
// A provider whose default source is a counter expanded through sha256 answers every
// behavioural question exactly as the real one does: its output is never constant, never
// zero, never repeated between two providers, and never repeated between two calls. It is
// also entirely predictable, and every key, nonce and signature seed the implementation
// produces would be recoverable from it. So the assertion is the constructor's own text,
// mechanically, and the matcher is proved on a control that is precisely that substitution
// rather than on a body that fails for some easier reason.
func TestNewCryptoProviderReadsTheProcessEntropySource(t *testing.T) {
	source := mustParseSource(t, macVerifySourcePath)
	got := source.statementsOf(t, "", "NewCryptoProvider")
	if !slices.Equal(got, newCryptoProviderStatements) {
		t.Errorf("NewCryptoProvider is\n%s\nwant\n%s",
			strings.Join(got, "\n"), strings.Join(newCryptoProviderStatements, "\n"))
	}
	if !slices.Contains(importPathsOf(source), cryptoRandImportPath) {
		t.Errorf("%s does not import %s, so nothing in it reads the operating system",
			macVerifySourcePath, cryptoRandImportPath)
	}
	control := mustParseText(t, "the deterministic control", newCryptoProviderDeterministicControl)
	if substituted := control.statementsOf(t, "", "NewCryptoProvider"); slices.Equal(substituted, newCryptoProviderStatements) {
		t.Errorf("the matcher read a constructor over a counter stream as the shape above")
	}
	if slices.Contains(importPathsOf(control), cryptoRandImportPath) {
		t.Errorf("the control claims to import %s", cryptoRandImportPath)
	}
}

// The import paths of one parsed file, quoted as they are written.
func importPathsOf(source parsedSource) []string {
	paths := []string{}
	for _, imported := range source.file.Imports {
		paths = append(paths, imported.Path.Value)
	}
	return paths
}

// Nothing is substituted for the source a caller passed. A constructor that quietly
// replaced a nil reader with crypto/rand would make a test believing it had pinned the
// randomness draw from production entropy instead, and the failing case it was written to
// reproduce would stop reproducing. Random over a nil reader has nowhere to read from, so
// the refusal is what says no substitution happened.
func TestNewCryptoProviderWithRandomSubstitutesNothing(t *testing.T) {
	crypto := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, nil)
	if recovered := recoveredPanic(func() { crypto.Random(32) }); recovered == nil {
		t.Errorf("a provider over a nil reader produced bytes, so it read something else")
	}
}

// The fields the one implementation is allowed to hold, and what makes sharing it safe.
// A field added later fails here on purpose: whether the new one is written after
// construction is the question this whole test exists to ask, and answering it is a line
// of thought rather than a line of code.
var providerFields = []string{"params *mls.SuiteParams", "random io.Reader"}

// The files that declare a method on the one implementation.
//
// Every gate below scans all of them rather than one named file. That is the shape of a
// defect this package already paid for: task 12 moved three methods into a second file,
// four whole provider invariants went on reading the first, and the identical receiver
// write failed or passed depending only on which file it was written in. A later task
// adding a fourth file fails here rather than quietly leaving its methods unscanned.
var providerMethodSourcePaths = []string{"crypto.go", "crypto_labels.go"}

// Every go file of this package, test files included. A method on the shared provider
// type is the thing being ruled out whichever file it is written in, and a file the scan
// does not read is a file the rule does not reach.
func packageSourcePaths(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list the package source: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("the package holds no go files, so nothing below scanned anything")
	}
	slices.Sort(paths)
	return paths
}

// Every method the interface names, read off the type rather than typed out.
//
// This is what the whole provider invariants below measure their own coverage against. A
// hand written list of methods is the thing that goes stale when the surface grows, and
// an invariant enumerating a surface that has moved on reports exactly what a complete
// one reports.
func providerMethodNames() []string {
	names := []string{}
	providerInterface := reflect.TypeOf((*CryptoProvider)(nil)).Elem()
	for i := 0; i < providerInterface.NumMethod(); i++ {
		names = append(names, providerInterface.Method(i).Name)
	}
	slices.Sort(names)
	return names
}

// The methods that answer with a size or a code point. They take no bytes and return no
// storage, so there is nothing for a buffer, aliasing or immutability invariant to look
// at; TestProviderSizes is what holds them.
var providerValueMethods = []string{"HashSize", "KeySize", "NonceSize", "Suite"}

// The methods tasks 15 and 16 still owe, which refuse to be called rather than answering.
//
// TestProviderStubsRefuseToBeCalled holds the refusal and reads this same list, so the
// two cannot drift. Implementing one means taking it off here, and taking it off here is
// what makes the invariants below demand it: a method that starts answering and is not
// added to their tables fails the coverage gate instead of going unexamined.
var providerStubMethods = []string{
	"DeriveKeyPair", "HpkeOpen", "HpkeSeal",
}

// One whole provider invariant's table, checked against the interface it is meant to
// cover. What is excused is named with its reason rather than left out, so a method that
// stops being excusable is a line somebody has to delete on purpose.
func assertCoversTheProviderSurface(t *testing.T, gate string, covered []string, excused map[string]string) {
	t.Helper()
	surface := providerMethodNames()
	want := []string{}
	for _, name := range surface {
		if slices.Contains(providerValueMethods, name) || slices.Contains(providerStubMethods, name) {
			continue
		}
		if _, isExcused := excused[name]; !isExcused {
			want = append(want, name)
		}
	}
	got := slices.Clone(covered)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("%s covers %v, want %v", gate, got, want)
	}
	for name := range excused {
		if !slices.Contains(surface, name) {
			t.Errorf("%s excuses %s, which the provider does not declare", gate, name)
		}
	}
}

// The lists above name methods this type really has. A misspelling in any of them would
// quietly shrink what the coverage gate demands, which is the same failure as a short
// table written out by hand.
func TestTheProviderSurfaceListsNameRealMethods(t *testing.T) {
	surface := providerMethodNames()
	for _, name := range slices.Concat(providerValueMethods, providerStubMethods) {
		if !slices.Contains(surface, name) {
			t.Errorf("%s is listed as part of the provider surface but is not a method of it", name)
		}
	}
	if len(surface) == 0 {
		t.Fatalf("the provider interface reported no methods, so every gate below excuses everything")
	}
}

// A provider that keeps a call count. Its methods are the real ones with one assignment
// added, which is the smallest version of the defect and the one a matcher aimed at
// something louder would miss.
const providerStatefulControl = `package mls

type suiteCryptoProvider struct {
	params *SuiteParams
	random io.Reader
	calls  int
}

func (self *suiteCryptoProvider) Hash(data []byte) []byte {
	self.calls++
	digest := sha256.Sum256(data)
	return digest[:]
}
`

// Spec A section 3.6, as a structure rather than as a hope. The concurrency test below
// cannot see a data race in this environment — -race needs cgo and there is no C compiler
// on this machine — so a provider carrying two shared fields written by every Hash call
// runs thirty two goroutines over them and reports nothing. What holds the claim instead
// is that the type has exactly the two fields it is documented to have, and that no method
// writes to either: an immutable value shared between goroutines cannot race, whether or
// not the detector is available to say so.
//
// The scan is over every file of the package rather than over one named file, and the
// files that turn out to declare a method are pinned. Reading a single file made this
// gate blind to a whole second half of the implementation, and the blindness was
// invisible: the gate found its subject, found no write, and passed.
func TestTheProviderHoldsNoMutableState(t *testing.T) {
	fields := []string{}
	providerType := reflect.TypeOf(suiteCryptoProvider{})
	for i := 0; i < providerType.NumField(); i++ {
		field := providerType.Field(i)
		fields = append(fields, field.Name+" "+field.Type.String())
	}
	if !slices.Equal(fields, providerFields) {
		t.Errorf("suiteCryptoProvider holds %v, want %v — a new field has to be shown never written",
			fields, providerFields)
	}
	declaring := []string{}
	declared := []string{}
	for _, path := range packageSourcePaths(t) {
		source := mustParseSource(t, path)
		methods := source.methodsOn(providerReceiver)
		if len(methods) == 0 {
			continue
		}
		declaring = append(declaring, path)
		declared = append(declared, methods...)
		if writes := source.receiverFieldWrites(providerReceiver); len(writes) != 0 {
			t.Errorf("a method of %s in %s writes to its receiver, so the provider is not safe to share: %v",
				providerReceiver, path, writes)
		}
	}
	if !slices.Equal(declaring, providerMethodSourcePaths) {
		t.Errorf("%s is implemented across %v, want %v — a file holding provider methods has to be scanned here",
			providerReceiver, declaring, providerMethodSourcePaths)
	}
	// and what those files hold really is the whole implementation, so a scan cannot be
	// complete over a set that has lost half of it
	slices.Sort(declared)
	if missing := missingFrom(providerMethodNames(), declared); len(missing) != 0 {
		t.Errorf("%v are methods of the provider that no scanned file declares", missing)
	}
	control := mustParseText(t, "the stateful control", providerStatefulControl)
	if writes := control.receiverFieldWrites(providerReceiver); len(writes) == 0 {
		t.Errorf("the matcher reported no receiver write in a method whose first statement is one")
	}
	if methods := control.methodsOn(providerReceiver); !slices.Equal(methods, []string{"Hash"}) {
		t.Errorf("the matcher read %v out of a control declaring one method", methods)
	}
}

// The members of want that got does not hold, so a failure names what is absent rather
// than printing two lists for a reader to difference by eye.
func missingFrom(want []string, got []string) []string {
	absent := []string{}
	for _, name := range want {
		if !slices.Contains(got, name) {
			absent = append(absent, name)
		}
	}
	return absent
}

// Every call returns storage of its own. A provider that answered out of one cached buffer
// would pass every equality test in this file — each answer is right when it is read — and
// would hand two goroutines the same array to write, and hand one caller a digest that
// changes under it when the next call is made. The aliasing test above compares a result
// against its input; this compares two results against each other, which is the direction
// a cache is invisible in.
//
// The table covers every method of the interface that answers with bytes, and the gate at
// the end says so: a later task that adds a method and not a row here fails rather than
// leaving the new one uncovered.
func TestProviderResultsAreFreshBuffers(t *testing.T) {
	crypto := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519,
		bytes.NewReader(bytes.Repeat(randomScript(t), 4)))
	prk := crypto.Extract([]byte("salt"), []byte("ikm"))
	key := bytes.Repeat([]byte{0x33}, crypto.KeySize())
	nonce := bytes.Repeat([]byte{0x44}, crypto.NonceSize())
	aad := []byte("aad")
	sealed, err := crypto.AeadSeal(key, nonce, aad, []byte("plaintext"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	signaturePriv, _, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("generate the key pair the signature row is built over: %v", err)
	}
	covered := []string{}
	for _, testCase := range []struct {
		name string
		call func() []byte
	}{
		{name: "Hash", call: func() []byte { return crypto.Hash([]byte("data")) }},
		{name: "Mac", call: func() []byte { return crypto.Mac([]byte("key"), []byte("data")) }},
		{name: "Extract", call: func() []byte { return crypto.Extract([]byte("salt"), []byte("ikm")) }},
		{name: "Expand", call: func() []byte { return crypto.Expand(prk, []byte("info"), 48) }},
		{name: "ExpandWithLabel", call: func() []byte {
			return crypto.ExpandWithLabel(prk, "label", []byte("context"), 48)
		}},
		{name: "DeriveSecret", call: func() []byte { return crypto.DeriveSecret(prk, "label") }},
		{name: "DeriveTreeSecret", call: func() []byte { return crypto.DeriveTreeSecret(prk, "label", 7, 48) }},
		{name: "AeadSeal", call: func() []byte {
			ciphertext, err := crypto.AeadSeal(key, nonce, aad, []byte("plaintext"))
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			return ciphertext
		}},
		{name: "AeadOpen", call: func() []byte {
			plaintext, err := crypto.AeadOpen(key, nonce, aad, sealed)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			return plaintext
		}},
		{name: "SignWithLabel", call: func() []byte {
			signature, err := crypto.SignWithLabel(signaturePriv, "label", []byte("content"))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			return signature
		}},
		{name: "SignatureKeyPair", call: func() []byte {
			priv, _, err := crypto.SignatureKeyPair()
			if err != nil {
				t.Fatalf("SignatureKeyPair: %v", err)
			}
			return priv
		}},
		{name: "Random", call: func() []byte { return crypto.Random(32) }},
	} {
		covered = append(covered, testCase.name)
		first, second := testCase.call(), testCase.call()
		if len(first) == 0 || len(second) == 0 {
			t.Errorf("%s returned nothing, so this shares nothing either", testCase.name)
			continue
		}
		if &first[0] == &second[0] {
			t.Errorf("two calls to %s returned the same storage", testCase.name)
			continue
		}
		// and holding the first result across the second call does not change it, which
		// is the failure a caller actually sees
		held := bytes.Clone(first)
		testCase.call()
		if !bytes.Equal(first, held) {
			t.Errorf("a result of %s changed from %x to %x when %s was called again",
				testCase.name, held, first, testCase.name)
		}
	}
	// the row above follows the private half, because a row can only follow one slice.
	// the public half is checked here rather than left out: a generator answering out of
	// storage it keeps would hand two callers the same public key as readily as the same
	// seed, and neither is visible in any signature either of them makes.
	firstPriv, firstPub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	secondPriv, secondPub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair a second time: %v", err)
	}
	if len(firstPub) == 0 || len(secondPub) == 0 {
		t.Fatalf("SignatureKeyPair answered with no public key, so this shares nothing either")
	}
	if &firstPub[0] == &secondPub[0] {
		t.Errorf("two key pairs answered out of the same public key storage")
	}
	if &firstPub[0] == &firstPriv[0] || &secondPub[0] == &secondPriv[0] {
		t.Errorf("a key pair answered with a public key cut from its own private key")
	}
	assertCoversTheProviderSurface(t, "the fresh buffer table", covered, map[string]string{
		"MacVerify":       "answers with a bool, so there is no storage for it to share",
		"VerifyWithLabel": "answers with an error, so there is no storage for it to share",
	})
}

// Two providers over the same byte stream produce the same bytes, which is what makes a
// failing interop or validation case reproducible rather than observed once.
func TestProviderWithRandomIsDeterministic(t *testing.T) {
	script := randomScript(t)
	first := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, bytes.NewReader(script))
	second := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, bytes.NewReader(script))
	if !bytes.Equal(first.Random(32), second.Random(32)) {
		t.Fatalf("two providers over the same stream disagreed")
	}
}

// Spec A section 3.6: the provider NewCryptoProvider returns is stateless and safe for
// concurrent use. Under -race this is the whole assertion; without it the race detector is
// absent and this exercises the methods concurrently without being able to report a race,
// so TestTheProviderHoldsNoMutableState is what carries the claim on a machine with no c
// compiler. Both are here because they fail on different things: this one on a method that
// disagrees with itself, that one on the shared field a disagreement would come from.
//
// Every method that answers deterministically is compared against an answer taken before
// the goroutines start, rather than merely called. That comparison is what a machine with
// no detector has: a provider answering out of one package level scratch array hands two
// goroutines the same storage, and what the caller sees is the other goroutine's bytes.
func TestProviderIsSafeForConcurrentUse(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	key := bytes.Repeat([]byte{0x0f}, crypto.KeySize())
	secret := bytes.Repeat([]byte{0x0f}, crypto.HashSize())
	nonce := make([]byte, crypto.NonceSize())
	message := []byte("data")
	tag := crypto.Mac(secret, message)
	sealed, err := crypto.AeadSeal(key, nonce, nil, message)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	signaturePriv, signaturePub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("generate the key pair the signature rows are built over: %v", err)
	}
	signature, err := crypto.SignWithLabel(signaturePriv, "label", message)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	operations := []struct {
		name string
		call func() []byte
	}{
		{name: "Hash", call: func() []byte { return crypto.Hash(message) }},
		{name: "Mac", call: func() []byte { return crypto.Mac(secret, message) }},
		{name: "MacVerify", call: func() []byte {
			if crypto.MacVerify(secret, message, tag) {
				return []byte{0x01}
			}
			return []byte{0x00}
		}},
		{name: "Extract", call: func() []byte { return crypto.Extract(secret, message) }},
		{name: "Expand", call: func() []byte { return crypto.Expand(secret, []byte("info"), 32) }},
		{name: "ExpandWithLabel", call: func() []byte {
			return crypto.ExpandWithLabel(secret, "label", []byte("context"), 48)
		}},
		{name: "DeriveSecret", call: func() []byte { return crypto.DeriveSecret(secret, "label") }},
		{name: "DeriveTreeSecret", call: func() []byte { return crypto.DeriveTreeSecret(secret, "label", 7, 48) }},
		{name: "AeadSeal", call: func() []byte {
			ciphertext, err := crypto.AeadSeal(key, nonce, nil, message)
			if err != nil {
				return nil
			}
			return ciphertext
		}},
		{name: "AeadOpen", call: func() []byte {
			plaintext, err := crypto.AeadOpen(key, nonce, nil, sealed)
			if err != nil {
				return nil
			}
			return plaintext
		}},
		{name: "SignWithLabel", call: func() []byte {
			produced, err := crypto.SignWithLabel(signaturePriv, "label", message)
			if err != nil {
				return nil
			}
			return produced
		}},
		{name: "VerifyWithLabel", call: func() []byte {
			if crypto.VerifyWithLabel(signaturePub, "label", message, signature) == nil {
				return []byte{0x01}
			}
			return []byte{0x00}
		}},
	}
	covered := []string{}
	want := make([][]byte, len(operations))
	for i, operation := range operations {
		covered = append(covered, operation.name)
		want[i] = operation.call()
		if len(want[i]) == 0 {
			t.Fatalf("%s answered with nothing before any goroutine started", operation.name)
		}
	}
	assertCoversTheProviderSurface(t, "the concurrency table", append(covered, "Random", "SignatureKeyPair"), nil)

	var waitGroup sync.WaitGroup
	for i := 0; i < 32; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for j := 0; j < 64; j++ {
				for k, operation := range operations {
					if !bytes.Equal(operation.call(), want[k]) {
						t.Errorf("%s disagreed with itself under concurrency", operation.name)
						return
					}
				}
				crypto.Random(32)
				// the two draws from the provider's reader, which answer differently
				// every time and so are exercised rather than compared
				if _, _, err := crypto.SignatureKeyPair(); err != nil {
					t.Errorf("SignatureKeyPair failed under concurrency: %v", err)
					return
				}
			}
		}()
	}
	waitGroup.Wait()
}

// The methods tasks 15 and 16 complete must refuse to be called until they are, rather
// than returning a zero value. A stub returning nil, nil from HpkeOpen would compile,
// satisfy the interface, and be a total authentication bypass for anyone calling it in
// the meantime. This is the counterpart of TestProviderHasNoRemainingStubs in task 16:
// that one asserts the list is empty at the end of the wave, this one asserts that what
// is still on the list is loud.
//
// The table is checked against providerStubMethods, which the whole provider invariants
// read to decide what they are allowed to skip. Implementing one of these means taking it
// off that list, and taking it off that list is what makes those invariants demand a row
// for it — so a method cannot become live and uncovered in the same commit.
func TestProviderStubsRefuseToBeCalled(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	refused := []string{}
	for _, testCase := range []struct {
		name string
		call func()
	}{
		{name: "HpkeSeal", call: func() { crypto.HpkeSeal(nil, nil, nil, nil) }},
		{name: "HpkeOpen", call: func() { crypto.HpkeOpen(nil, nil, nil, nil, nil) }},
		{name: "DeriveKeyPair", call: func() { crypto.DeriveKeyPair(nil) }},
	} {
		refused = append(refused, testCase.name)
		if recovered := recoveredPanic(testCase.call); recovered == nil {
			t.Errorf("%s returned instead of refusing; an unimplemented method must not answer", testCase.name)
		}
	}
	slices.Sort(refused)
	if !slices.Equal(refused, providerStubMethods) {
		t.Errorf("this table refuses %v, while the invariants skip %v", refused, providerStubMethods)
	}
}

// A provider that answers what the real one answers with every byte flipped, and records
// what it was asked.
//
// This exists for the constructions that take a CryptoProvider as a parameter rather than
// as a receiver. Nothing about their output says which provider computed it: one that
// reached for crypto/sha256 directly, or built a provider of its own out of a hardcoded
// suite, agrees with every published corpus and every known answer in this package,
// because the suite in those corpora is the suite it hardcoded. A provider that is not the
// real one is the only input that tells the two apart — a construction that routed through
// the parameter answers differently over this one, and a construction that ignored the
// parameter answers exactly the same.
//
// The methods are written out rather than promoted from an embedded CryptoProvider on
// purpose. A promoted method is one the compiler supplies, so a method added to the
// interface would arrive here already implemented, tagging nothing and quietly narrowing
// what the gates that use this can see — which is the shape task 12 paid for. Written out,
// the build stops until somebody decides what the new method does here.
type taggingCryptoProvider struct {
	inner CryptoProvider
	calls []string
}

// Drift between the interface and this wrapper fails at build rather than at the gate that
// reads it, which is the whole reason the methods are written out.
var _ CryptoProvider = (*taggingCryptoProvider)(nil)

// One answer, recorded and flipped. Cloning rather than flipping in place matters: what
// the whole provider invariants hold is that the real provider hands out storage nobody
// else writes into, and a wrapper that flipped the array it was handed would break that
// from the test side.
func (self *taggingCryptoProvider) tagged(name string, answer []byte) []byte {
	self.calls = append(self.calls, name)
	flipped := bytes.Clone(answer)
	for i := range flipped {
		flipped[i] ^= 0x5a
	}
	return flipped
}

// One call whose answer carries no bytes to flip, recorded and passed through. A
// construction that reached only for a size still shows up in the call log, so a gate can
// say whether the provider was touched at all separately from whether its answer was used.
func (self *taggingCryptoProvider) passedThrough(name string) {
	self.calls = append(self.calls, name)
}

func (self *taggingCryptoProvider) Suite() CipherSuite {
	self.passedThrough("Suite")
	return self.inner.Suite()
}

func (self *taggingCryptoProvider) HashSize() int {
	self.passedThrough("HashSize")
	return self.inner.HashSize()
}

func (self *taggingCryptoProvider) KeySize() int {
	self.passedThrough("KeySize")
	return self.inner.KeySize()
}

func (self *taggingCryptoProvider) NonceSize() int {
	self.passedThrough("NonceSize")
	return self.inner.NonceSize()
}

func (self *taggingCryptoProvider) Hash(data []byte) []byte {
	return self.tagged("Hash", self.inner.Hash(data))
}

func (self *taggingCryptoProvider) Mac(key []byte, data []byte) []byte {
	return self.tagged("Mac", self.inner.Mac(key, data))
}

func (self *taggingCryptoProvider) MacVerify(key []byte, data []byte, tag []byte) bool {
	self.passedThrough("MacVerify")
	return self.inner.MacVerify(key, data, tag)
}

func (self *taggingCryptoProvider) Extract(salt []byte, ikm []byte) []byte {
	return self.tagged("Extract", self.inner.Extract(salt, ikm))
}

func (self *taggingCryptoProvider) Expand(prk []byte, info []byte, length int) []byte {
	return self.tagged("Expand", self.inner.Expand(prk, info, length))
}

func (self *taggingCryptoProvider) ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte {
	return self.tagged("ExpandWithLabel", self.inner.ExpandWithLabel(secret, label, context, length))
}

func (self *taggingCryptoProvider) DeriveSecret(secret []byte, label string) []byte {
	return self.tagged("DeriveSecret", self.inner.DeriveSecret(secret, label))
}

func (self *taggingCryptoProvider) DeriveTreeSecret(secret []byte, label string, generation uint32, length int) []byte {
	return self.tagged("DeriveTreeSecret", self.inner.DeriveTreeSecret(secret, label, generation, length))
}

func (self *taggingCryptoProvider) AeadSeal(key []byte, nonce []byte, aad []byte, plaintext []byte) ([]byte, error) {
	ciphertext, err := self.inner.AeadSeal(key, nonce, aad, plaintext)
	if err != nil {
		self.passedThrough("AeadSeal")
		return nil, err
	}
	return self.tagged("AeadSeal", ciphertext), nil
}

func (self *taggingCryptoProvider) AeadOpen(key []byte, nonce []byte, aad []byte, ciphertext []byte) ([]byte, error) {
	plaintext, err := self.inner.AeadOpen(key, nonce, aad, ciphertext)
	if err != nil {
		self.passedThrough("AeadOpen")
		return nil, err
	}
	return self.tagged("AeadOpen", plaintext), nil
}

func (self *taggingCryptoProvider) Random(n int) []byte {
	return self.tagged("Random", self.inner.Random(n))
}

func (self *taggingCryptoProvider) SignWithLabel(priv SignaturePrivateKey, label string, content []byte) ([]byte, error) {
	signature, err := self.inner.SignWithLabel(priv, label, content)
	if err != nil {
		self.passedThrough("SignWithLabel")
		return nil, err
	}
	return self.tagged("SignWithLabel", signature), nil
}

func (self *taggingCryptoProvider) VerifyWithLabel(pub SignaturePublicKey, label string, content []byte, sig []byte) error {
	self.passedThrough("VerifyWithLabel")
	return self.inner.VerifyWithLabel(pub, label, content, sig)
}

func (self *taggingCryptoProvider) HpkeSeal(pub HpkePublicKey, info []byte, aad []byte, plaintext []byte) ([]byte, []byte, error) {
	self.passedThrough("HpkeSeal")
	return self.inner.HpkeSeal(pub, info, aad, plaintext)
}

func (self *taggingCryptoProvider) HpkeOpen(priv HpkePrivateKey, kemOutput []byte, info []byte, aad []byte, ciphertext []byte) ([]byte, error) {
	self.passedThrough("HpkeOpen")
	return self.inner.HpkeOpen(priv, kemOutput, info, aad, ciphertext)
}

func (self *taggingCryptoProvider) DeriveKeyPair(ikm []byte) (HpkePrivateKey, HpkePublicKey, error) {
	self.passedThrough("DeriveKeyPair")
	return self.inner.DeriveKeyPair(ikm)
}

// Both halves are flipped, so a construction reading either one of them answers
// differently over this provider. Two entries land in the call log for one call, which the
// log is fine with: it is read to explain a failure and never compared for length.
func (self *taggingCryptoProvider) SignatureKeyPair() (SignaturePrivateKey, SignaturePublicKey, error) {
	priv, pub, err := self.inner.SignatureKeyPair()
	if err != nil {
		self.passedThrough("SignatureKeyPair")
		return nil, nil, err
	}
	return SignaturePrivateKey(self.tagged("SignatureKeyPair", priv)),
		SignaturePublicKey(self.tagged("SignatureKeyPair", pub)), nil
}

// The methods the tagging provider hands back unchanged, named with the reason rather than
// left out. Neither of the two is a stub, and neither answers with bytes: there is nothing
// in a yes, a no or a refusal for a flip to change, so a construction that routed a
// comparison through either cannot be separated by a different answer. The stubs are skipped
// by assertCoversTheProviderSurface itself, so implementing one is what makes the gate
// below demand it be tagged.
var taggingProviderPassesThrough = map[string]string{
	"MacVerify":       "answers a bool, and flipping has nothing to change in a yes or a no",
	"VerifyWithLabel": "answers an error, and flipping has nothing to change in a refusal",
}

// The tagging provider really does answer differently, method by method.
//
// Without this, every gate that reads it is vacuous in the direction that matters. A
// tagged method that stopped tagging would make the constructions agree with the real
// provider, and the routing gate would report that none of them use the provider they were
// handed; drop the flip from only the one method a construction happens to call and that
// gate reports a clean run while observing nothing at all. Each row is one method's answer
// over the tagging provider against the same method's answer over the provider inside it.
//
// The provider underneath draws from a constant reader, because the Random row otherwise
// compares two draws that differ on their own whatever the wrapper does.
func TestTheTaggingProviderAnswersDifferentlyThanTheRealOne(t *testing.T) {
	plain := mustProviderOver(t, CipherSuiteX25519ChaCha20Sha256Ed25519, constantReader{value: 0x3d})
	tagging := &taggingCryptoProvider{inner: plain}
	secret := bytes.Repeat([]byte{0x4b}, plain.HashSize())
	key := bytes.Repeat([]byte{0x11}, plain.KeySize())
	nonce := bytes.Repeat([]byte{0x22}, plain.NonceSize())
	sealed, err := plain.AeadSeal(key, nonce, []byte("aad"), []byte("plaintext"))
	if err != nil {
		t.Fatalf("seal the ciphertext the AeadOpen row reads: %v", err)
	}
	// drawn from the provider underneath rather than written out, so the row below is
	// built over whatever length the suite fixes
	signaturePriv, _, err := plain.SignatureKeyPair()
	if err != nil {
		t.Fatalf("generate the key the SignWithLabel row is built over: %v", err)
	}
	tagged := []string{}
	for _, testCase := range []struct {
		name string
		call func(crypto CryptoProvider) []byte
	}{
		{name: "Hash", call: func(crypto CryptoProvider) []byte { return crypto.Hash([]byte("data")) }},
		{name: "Mac", call: func(crypto CryptoProvider) []byte { return crypto.Mac(key, []byte("data")) }},
		{name: "Extract", call: func(crypto CryptoProvider) []byte { return crypto.Extract(nil, secret) }},
		{name: "Expand", call: func(crypto CryptoProvider) []byte { return crypto.Expand(secret, []byte("info"), 32) }},
		{name: "ExpandWithLabel", call: func(crypto CryptoProvider) []byte {
			return crypto.ExpandWithLabel(secret, "label", []byte("context"), 32)
		}},
		{name: "DeriveSecret", call: func(crypto CryptoProvider) []byte { return crypto.DeriveSecret(secret, "label") }},
		{name: "DeriveTreeSecret", call: func(crypto CryptoProvider) []byte {
			return crypto.DeriveTreeSecret(secret, "label", 7, 32)
		}},
		{name: "AeadSeal", call: func(crypto CryptoProvider) []byte {
			out, sealErr := crypto.AeadSeal(key, nonce, []byte("aad"), []byte("plaintext"))
			if sealErr != nil {
				t.Fatalf("AeadSeal: %v", sealErr)
			}
			return out
		}},
		{name: "AeadOpen", call: func(crypto CryptoProvider) []byte {
			out, openErr := crypto.AeadOpen(key, nonce, []byte("aad"), sealed)
			if openErr != nil {
				t.Fatalf("AeadOpen: %v", openErr)
			}
			return out
		}},
		{name: "SignWithLabel", call: func(crypto CryptoProvider) []byte {
			signature, signErr := crypto.SignWithLabel(signaturePriv, "label", []byte("content"))
			if signErr != nil {
				t.Fatalf("SignWithLabel: %v", signErr)
			}
			return signature
		}},
		{name: "SignatureKeyPair", call: func(crypto CryptoProvider) []byte {
			priv, pub, keyErr := crypto.SignatureKeyPair()
			if keyErr != nil {
				t.Fatalf("SignatureKeyPair: %v", keyErr)
			}
			return concatBytes(priv, pub)
		}},
		{name: "Random", call: func(crypto CryptoProvider) []byte { return crypto.Random(32) }},
	} {
		tagged = append(tagged, testCase.name)
		answer := testCase.call(plain)
		flipped := testCase.call(tagging)
		if len(answer) == 0 {
			t.Errorf("%s answered no bytes, so this row separates nothing", testCase.name)
			continue
		}
		if bytes.Equal(answer, flipped) {
			t.Errorf("%s answers the same over the tagging provider as over the real one, so nothing routed through it is observable",
				testCase.name)
		}
		if len(answer) != len(flipped) {
			t.Errorf("%s answered %d bytes over the tagging provider and %d over the real one; a tag must not change the length",
				testCase.name, len(flipped), len(answer))
		}
	}
	// and the rows are every method the tagging provider claims to tag, so a method that
	// stops being a stub is a row somebody has to write rather than one whose answer goes
	// on being passed through
	assertCoversTheProviderSurface(t, "the tagging provider", tagged, taggingProviderPassesThrough)
}

// One function this package declares at package level, with the file that declares it and
// the parameter types it is written to take.
type packageLevelFunction struct {
	file       string
	name       string
	parameters []string
}

// What one scan of the package's source read: the functions, and the files they came out
// of.
//
// The files are carried because the functions alone cannot say what was missed. A scan
// that stopped reading a file returns a shorter list of functions, and a shorter list of
// functions still satisfies every gate whose table was never extended — which is the
// understatement this package has paid for repeatedly. The file list is what a gate can
// compare against the package's own source.
type packageLevelScan struct {
	files     []string
	functions []packageLevelFunction
}

// The package level functions of one parsed file.
//
// Parameter types come back rendered and one per name, so a signature written
// func f(a, b []byte) reads the same here as one written func f(a []byte, b []byte). A
// gate that filters on a type is then filtering on what the compiler sees rather than on
// how the line happened to be spaced, and the grouped form is the one a filter over the
// file's characters would misread.
func packageLevelFunctionsIn(parsed parsedSource, path string) []packageLevelFunction {
	functions := []packageLevelFunction{}
	for _, declaration := range parsed.file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Recv != nil {
			continue
		}
		parameters := []string{}
		for _, field := range function.Type.Params.List {
			rendered := parsed.render(field.Type)
			written := len(field.Names)
			if written == 0 {
				written = 1
			}
			for i := 0; i < written; i++ {
				parameters = append(parameters, rendered)
			}
		}
		functions = append(functions, packageLevelFunction{
			file:       path,
			name:       function.Name.Name,
			parameters: parameters,
		})
	}
	return functions
}

// Every package level function of the package's non test source.
//
// The scan is every file rather than a named one, which is the shape task 12 paid for: a
// gate that enumerates a filename goes on reporting a clean run while the thing it guards
// is written next door. Test files are skipped because what these gates are about is the
// surface the package ships, and a helper written for a table is not a construction
// anybody outside the tests calls.
//
// TestThePackageLevelFunctionScanReadsEveryNonTestFile writes that same rule out a second
// time and compares. The repetition is deliberate: a rule stated once here and read by
// every gate is a rule that can be narrowed in one place, and every gate reading it would
// narrow with it and report a clean run.
func packageLevelFunctions(t *testing.T) packageLevelScan {
	t.Helper()
	scan := packageLevelScan{files: []string{}, functions: []packageLevelFunction{}}
	for _, path := range packageSourcePaths(t) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		scan.files = append(scan.files, path)
		scan.functions = append(scan.functions, packageLevelFunctionsIn(mustParseSource(t, path), path)...)
	}
	if len(scan.functions) == 0 {
		t.Fatalf("the package's non test source declares no package level functions, so every gate reading this demands nothing")
	}
	return scan
}

// The names of the package level functions whose parameters include one of a given type.
//
// Absence is fatal rather than clean, for the same reason every other enumeration here is:
// a filter that stopped matching leaves the gate reading it demanding nothing, and a gate
// that demands nothing reports exactly what a complete one reports.
func packageLevelFunctionsTaking(t *testing.T, parameter string) []string {
	t.Helper()
	names := []string{}
	for _, function := range packageLevelFunctions(t).functions {
		if slices.Contains(function.parameters, parameter) {
			names = append(names, function.name)
		}
	}
	if len(names) == 0 {
		t.Fatalf("no package level function of this package takes a %s, so the gate reading this demands nothing", parameter)
	}
	slices.Sort(names)
	return names
}

// The scan reads the whole package rather than the part a gate's table already covers.
//
// A scan narrowed by one filename is invisible from the gates that read it: they compare
// their tables against a shorter list of declared functions, find it matches, and report
// the clean run they would report if nothing had been narrowed at all. What says otherwise
// is the package's own file list, written out here a second time rather than taken from
// the scan.
func TestThePackageLevelFunctionScanReadsEveryNonTestFile(t *testing.T) {
	scanned := packageLevelFunctions(t).files
	source := []string{}
	for _, path := range packageSourcePaths(t) {
		if !strings.HasSuffix(path, "_test.go") {
			source = append(source, path)
		}
	}
	if !slices.Equal(scanned, source) {
		t.Errorf("the package level function scan read %v, and this package's non test source is %v", scanned, source)
	}
}

// The named types of one parsed file whose underlying type is a byte slice.
//
// A construction taking an HpkePublicKey is handed a caller's array exactly as one taking
// a []byte is, and to the compiler the two are the same storage. A filter matching the
// spelling []byte alone would drop nine of this package's constructions out of the class
// below and report the clean run a complete filter reports.
func packageByteSliceTypeNamesIn(parsed parsedSource) []string {
	names := []string{}
	for _, declaration := range parsed.file.Decls {
		types, isTypeDeclaration := declaration.(*ast.GenDecl)
		if !isTypeDeclaration || types.Tok != token.TYPE {
			continue
		}
		for _, specification := range types.Specs {
			named, isNamed := specification.(*ast.TypeSpec)
			if !isNamed {
				continue
			}
			slice, isSlice := named.Type.(*ast.ArrayType)
			if !isSlice || slice.Len != nil || parsed.render(slice.Elt) != "byte" {
				continue
			}
			names = append(names, named.Name.Name)
		}
	}
	return names
}

// Every type of this package's non test source that is a byte slice under another name.
func packageByteSliceTypeNames(t *testing.T) []string {
	t.Helper()
	names := []string{}
	for _, path := range packageLevelFunctions(t).files {
		names = append(names, packageByteSliceTypeNamesIn(mustParseSource(t, path))...)
	}
	if len(names) == 0 {
		t.Fatalf("this package names no byte slice type, so the class below is filtered on a spelling")
	}
	slices.Sort(names)
	return names
}

// Every package level construction of this package that is handed a caller's bytes.
//
// This is the class the immutability gate below covers, read off the parse tree rather
// than typed out. A construction taking no byte slice cannot write into an array it was
// handed, so the filter is the property rather than a list somebody keeps in step.
func packageLevelFunctionsTakingCallerBytes(t *testing.T) []string {
	t.Helper()
	byteSlices := slices.Concat([]string{"[]byte"}, packageByteSliceTypeNames(t))
	names := []string{}
	for _, function := range packageLevelFunctions(t).functions {
		for _, parameter := range function.parameters {
			if slices.Contains(byteSlices, parameter) {
				names = append(names, function.name)
				break
			}
		}
	}
	if len(names) == 0 {
		t.Fatalf("no package level function of this package is handed bytes, so the gate below demands nothing")
	}
	slices.Sort(names)
	return names
}

// The constructions whose answer carries no bytes, named with what they answer instead.
//
// The aliasing, determinism and fresh storage halves of the gate below read a construction's
// byte results, and these have none to read. Naming them rather than letting a row quietly
// answer with nothing is what keeps the gate from passing over a row that stopped returning
// its result: a name that is not here must answer with bytes, and a name that is here must
// not.
var packageConstructionsAnsweringNoBytes = map[string]string{
	"hpkeNewAead":      "answers a cipher.AEAD over the key, and the key is what this reads",
	"hpkeKeySchedule":  "answers an *HpkeContext holding the derivations rather than the bytes",
	"HpkeSetupBaseR":   "answers an *HpkeContext, the recipient half having no wire output",
	"X25519PrivateKey": "answers an *ecdh.PrivateKey, which is the library's own storage",
	"X25519PublicKey":  "answers an *ecdh.PublicKey, which is the library's own storage",
}

// A construction handed a caller's bytes that this gate does not hold, named with the
// reason. Nothing is excusable today; the map exists so that a construction which cannot
// be held is a line somebody writes on purpose rather than one left out of the table.
var packageConstructionsOverBorrowedBytes = map[string]string{}

// Every construction this package hands a caller's array leaves that array alone, answers
// the same thing twice and answers out of storage of its own.
//
// What these are handed is a group's own secret, a serialized key package, somebody's
// framed proposal, a peer's public key or a ciphertext off the wire, and every one of them
// is read again after the call. A construction that wrote into the array its argument was
// cut from would corrupt the object it was asked to name, and one that answered out of
// storage it keeps would hand two callers the same bytes. Neither is visible in any digest,
// any published vector or any round trip: the answer is right, and the caller's buffer is
// wrong afterwards.
//
// The arguments go through a recorder, so each is cut from a longer array whose spare
// capacity holds a pattern rather than zeros: a construction that appends a byte to save an
// allocation leaves len alone, and against a zeroed array it would leave the bytes past len
// looking untouched as well.
//
// The scope is the package and not one file. The gate this replaces enumerated
// crypto_labels.go, which is the defect task 12 paid for one layer over — the identical
// scribble into a caller's spare capacity failed in the file the gate named and passed in
// every other file of the package, and hpke.go's fourteen constructions over caller bytes
// were held by nothing at all. It lives here rather than beside the labelled constructions
// for the same reason: the class is the package's, so the gate is the package's.
//
// Determinism is checkable for the three constructions that draw an ephemeral key because
// they are handed the reader they draw from, and a constant reader hands them the same key
// twice.
func TestEveryConstructionInThisPackageLeavesItsInputAlone(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("look up the suite these rows are built over: %v", err)
	}
	value := bytes.Repeat([]byte{0x21}, 96)
	suiteId := hpkeSuiteId(params)
	kemSuiteId := hpkeKemSuiteId(params)
	ikm := bytes.Repeat([]byte{0x31}, params.Nsk)
	priv, pub, err := HpkeDeriveKeyPair(params, ikm)
	if err != nil {
		t.Fatalf("derive the key pair these rows are built over: %v", err)
	}
	sharedSecret, kemOutput, err := hpkeEncap(constantReader{value: 0x77}, params, pub)
	if err != nil {
		t.Fatalf("encapsulate the shared secret these rows are built over: %v", err)
	}
	info := []byte("the info every hpke row carries")
	aad := []byte("the aad every hpke row carries")
	plaintext := []byte("the plaintext every hpke row carries")
	sealedKemOutput, sealedCiphertext, err := HpkeSealBase(constantReader{value: 0x66}, params, pub, info, aad, plaintext)
	if err != nil {
		t.Fatalf("seal the ciphertext the open rows read: %v", err)
	}
	key := bytes.Repeat([]byte{0x44}, params.Nk)
	covered := []string{}
	for _, testCase := range []struct {
		name string
		call func(take func(content []byte) []byte) [][]byte
	}{
		{name: "mlsKdfLabel", call: func(take func([]byte) []byte) [][]byte {
			return [][]byte{mlsKdfLabel("label", take(value), 32)}
		}},
		{name: "mlsSignContent", call: func(take func([]byte) []byte) [][]byte {
			return [][]byte{mlsSignContent("label", take(value))}
		}},
		{name: "RefHash", call: func(take func([]byte) []byte) [][]byte {
			return [][]byte{RefHash(crypto, "MLS 1.0 a label", take(value))}
		}},
		{name: "MakeKeyPackageRef", call: func(take func([]byte) []byte) [][]byte {
			return [][]byte{MakeKeyPackageRef(crypto, take(value))}
		}},
		{name: "MakeProposalRef", call: func(take func([]byte) []byte) [][]byte {
			return [][]byte{MakeProposalRef(crypto, take(value))}
		}},
		{name: "hpkeLabeledExtract", call: func(take func([]byte) []byte) [][]byte {
			return [][]byte{hpkeLabeledExtract(take(kemSuiteId), take(ikm), "eae_prk", take(sharedSecret))}
		}},
		{name: "hpkeLabeledExpand", call: func(take func([]byte) []byte) [][]byte {
			expanded, expandErr := hpkeLabeledExpand(take(kemSuiteId), take(sharedSecret), "shared_secret", take(info), 32)
			if expandErr != nil {
				t.Fatalf("hpkeLabeledExpand: %v", expandErr)
			}
			return [][]byte{expanded}
		}},
		{name: "HpkeDeriveKeyPair", call: func(take func([]byte) []byte) [][]byte {
			derivedPriv, derivedPub, deriveErr := HpkeDeriveKeyPair(params, take(ikm))
			if deriveErr != nil {
				t.Fatalf("HpkeDeriveKeyPair: %v", deriveErr)
			}
			return [][]byte{derivedPriv, derivedPub}
		}},
		{name: "hpkeExtractAndExpand", call: func(take func([]byte) []byte) [][]byte {
			secret, expandErr := hpkeExtractAndExpand(params, take(sharedSecret), take(kemOutput))
			if expandErr != nil {
				t.Fatalf("hpkeExtractAndExpand: %v", expandErr)
			}
			return [][]byte{secret}
		}},
		{name: "hpkeEncap", call: func(take func([]byte) []byte) [][]byte {
			secret, encapsulated, encapErr := hpkeEncap(constantReader{value: 0x77}, params, HpkePublicKey(take(pub)))
			if encapErr != nil {
				t.Fatalf("hpkeEncap: %v", encapErr)
			}
			return [][]byte{secret, encapsulated}
		}},
		{name: "hpkeEncapDeterministic", call: func(take func([]byte) []byte) [][]byte {
			secret, encapsulated, encapErr := hpkeEncapDeterministic(params, HpkePublicKey(take(pub)), HpkePrivateKey(take(priv)))
			if encapErr != nil {
				t.Fatalf("hpkeEncapDeterministic: %v", encapErr)
			}
			return [][]byte{secret, encapsulated}
		}},
		{name: "hpkeDecap", call: func(take func([]byte) []byte) [][]byte {
			secret, decapErr := hpkeDecap(params, HpkePrivateKey(take(priv)), take(kemOutput))
			if decapErr != nil {
				t.Fatalf("hpkeDecap: %v", decapErr)
			}
			return [][]byte{secret}
		}},
		{name: "hpkeNewAead", call: func(take func([]byte) []byte) [][]byte {
			if _, aeadErr := hpkeNewAead(params, take(key)); aeadErr != nil {
				t.Fatalf("hpkeNewAead: %v", aeadErr)
			}
			return nil
		}},
		{name: "hpkeKeyScheduleContext", call: func(take func([]byte) []byte) [][]byte {
			return [][]byte{hpkeKeyScheduleContext(take(suiteId), take(info))}
		}},
		{name: "hpkeKeySchedule", call: func(take func([]byte) []byte) [][]byte {
			if _, scheduleErr := hpkeKeySchedule(params, take(sharedSecret), take(info)); scheduleErr != nil {
				t.Fatalf("hpkeKeySchedule: %v", scheduleErr)
			}
			return nil
		}},
		{name: "HpkeSetupBaseS", call: func(take func([]byte) []byte) [][]byte {
			encapsulated, _, setupErr := HpkeSetupBaseS(constantReader{value: 0x66}, params, HpkePublicKey(take(pub)), take(info))
			if setupErr != nil {
				t.Fatalf("HpkeSetupBaseS: %v", setupErr)
			}
			return [][]byte{encapsulated}
		}},
		{name: "HpkeSetupBaseR", call: func(take func([]byte) []byte) [][]byte {
			_, setupErr := HpkeSetupBaseR(params, HpkePrivateKey(take(priv)), take(sealedKemOutput), take(info))
			if setupErr != nil {
				t.Fatalf("HpkeSetupBaseR: %v", setupErr)
			}
			return nil
		}},
		{name: "HpkeSealBase", call: func(take func([]byte) []byte) [][]byte {
			encapsulated, ciphertext, sealErr := HpkeSealBase(constantReader{value: 0x66}, params,
				HpkePublicKey(take(pub)), take(info), take(aad), take(plaintext))
			if sealErr != nil {
				t.Fatalf("HpkeSealBase: %v", sealErr)
			}
			return [][]byte{encapsulated, ciphertext}
		}},
		{name: "HpkeOpenBase", call: func(take func([]byte) []byte) [][]byte {
			opened, openErr := HpkeOpenBase(params, HpkePrivateKey(take(priv)), take(sealedKemOutput),
				take(info), take(aad), take(sealedCiphertext))
			if openErr != nil {
				t.Fatalf("HpkeOpenBase: %v", openErr)
			}
			return [][]byte{opened}
		}},
		{name: "X25519PrivateKey", call: func(take func([]byte) []byte) [][]byte {
			if _, keyErr := X25519PrivateKey(take(priv)); keyErr != nil {
				t.Fatalf("X25519PrivateKey: %v", keyErr)
			}
			return nil
		}},
		{name: "X25519PublicKey", call: func(take func([]byte) []byte) [][]byte {
			if _, keyErr := X25519PublicKey(take(pub)); keyErr != nil {
				t.Fatalf("X25519PublicKey: %v", keyErr)
			}
			return nil
		}},
	} {
		covered = append(covered, testCase.name)
		recorder := &argumentRecorder{}
		first := testCase.call(recorder.take)
		if len(recorder.arrays) == 0 {
			t.Errorf("%s was handed nothing, so this row observed nothing", testCase.name)
			continue
		}
		if changed := recorder.changed(); len(changed) != 0 {
			t.Errorf("%s changed the storage behind arguments %v of the %d it was handed",
				testCase.name, changed, len(recorder.arrays))
		}
		_, answersNoBytes := packageConstructionsAnsweringNoBytes[testCase.name]
		if answersNoBytes {
			if len(first) != 0 {
				t.Errorf("%s is named as answering no bytes and answered %d results", testCase.name, len(first))
			}
			continue
		}
		if len(first) == 0 {
			t.Errorf("%s answered with nothing, so this row observed nothing", testCase.name)
			continue
		}
		second := testCase.call((&argumentRecorder{}).take)
		if len(second) != len(first) {
			t.Errorf("%s answered %d results and then %d for one input", testCase.name, len(first), len(second))
			continue
		}
		for i, answer := range first {
			if len(answer) == 0 {
				t.Errorf("%s answered nothing in result %d, so that result observed nothing", testCase.name, i)
				continue
			}
			if recorder.aliases(answer) {
				t.Errorf("%s answered result %d over one of its arguments", testCase.name, i)
			}
			if !bytes.Equal(answer, second[i]) {
				t.Errorf("%s answered %x and then %x in result %d for one input",
					testCase.name, answer, second[i], i)
			}
			if len(second[i]) != 0 && &answer[0] == &second[i][0] {
				t.Errorf("two calls to %s answered result %d out of the same array", testCase.name, i)
			}
		}
	}
	// and the table names every construction this package hands a caller's bytes rather
	// than the ones this test happened to think of
	declared := packageLevelFunctionsTakingCallerBytes(t)
	want := []string{}
	for _, name := range declared {
		if _, isExcused := packageConstructionsOverBorrowedBytes[name]; !isExcused {
			want = append(want, name)
		}
	}
	slices.Sort(covered)
	if !slices.Equal(covered, want) {
		t.Errorf("this gate covers %v, and the package hands bytes to %v", covered, want)
	}
	for name := range packageConstructionsOverBorrowedBytes {
		if !slices.Contains(declared, name) {
			t.Errorf("the gate excuses %s, which no construction of this package declares", name)
		}
	}
	for name := range packageConstructionsAnsweringNoBytes {
		if !slices.Contains(declared, name) {
			t.Errorf("%s is named as answering no bytes, and no construction of this package declares it", name)
		}
	}
}

// The byte slice type scan reads a name as the storage it is.
//
// Every construction of hpke.go takes its keys under a name rather than as a []byte, so a
// scan that read only the spelling []byte would drop them out of the class above — and a
// class that shrank is a gate that demands less while reporting exactly what it reported
// before. The control names a byte slice, a slice of something else, an array of bytes and
// a name for a name, so a scan that matched on the word byte alone fails here.
func TestTheByteSliceTypeScanReadsNamedStorage(t *testing.T) {
	parsed := mustParseText(t, "the named storage control", namedByteSliceControl)
	found := packageByteSliceTypeNamesIn(parsed)
	slices.Sort(found)
	if want := []string{"AnotherKey", "SomeKey"}; !slices.Equal(found, want) {
		t.Errorf("the byte slice type scan read %v out of the control, want %v", found, want)
	}
	// and the real package's named storage is read the same way
	if named := packageByteSliceTypeNames(t); !slices.Contains(named, "HpkePublicKey") {
		t.Errorf("the byte slice type scan read %v out of this package, which names HpkePublicKey", named)
	}
}

// Four type declarations, one of which is a byte slice under another name and three of
// which are not. Every byte slice scan above runs on this as well, so one that started
// matching a fixed array or a slice of something else fails here rather than widening the
// class in silence.
const namedByteSliceControl = `package mls

type SomeKey []byte

type AnotherKey []byte

type NotAKey []uint16

type NotASlice [32]byte

type NotStorage SomeKey
`

// The recorder can see the smallest write a construction makes into its caller's array.
//
// Every immutability gate in this package is only as good as what the recorder fills the
// spare capacity with. Fill it with zeros and the commonest defect of the class — an
// append that saves an allocation by writing a zero byte past the caller's length —
// changes nothing the recorder can compare, and every row of every gate above reports the
// clean run it reports today. Measured: with the pattern replaced by zeros, a scribble
// into hpkeDecap's kem output survives the whole package.
//
// The aliasing half has the same shape. A result cut from the middle of a caller's array
// shares that array's storage exactly as one cut from the front does, and a check that
// compared only against each argument's first byte would call it fresh.
func TestTheArgumentRecorderSeesTheSmallestWrite(t *testing.T) {
	appended := &argumentRecorder{}
	argument := appended.take(bytes.Repeat([]byte{0x11}, 8))
	_ = append(argument, 0x00)
	if changed := appended.changed(); len(changed) != 1 {
		t.Errorf("the recorder reported %v changed after a zero was appended into the spare capacity behind its one argument, want the argument",
			changed)
	}
	untouched := &argumentRecorder{}
	untouched.take(bytes.Repeat([]byte{0x11}, 8))
	if changed := untouched.changed(); len(changed) != 0 {
		t.Errorf("the recorder reported %v changed after nothing was written, so it cannot tell a write from a read", changed)
	}
	aliasing := &argumentRecorder{}
	borrowed := aliasing.take(bytes.Repeat([]byte{0x11}, 8))
	if !aliasing.aliases(borrowed[4:]) {
		t.Errorf("the recorder read a result cut from the middle of its argument as storage of its own")
	}
	if aliasing.aliases(bytes.Repeat([]byte{0x11}, 8)) {
		t.Errorf("the recorder read a fresh array holding the same bytes as one of its arguments")
	}
}
