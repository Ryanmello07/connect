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
	"io"
	"os"
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
		if recovered := recoveredPanic(func() { crypto.Expand(prk, []byte("info"), length) }); recovered == nil {
			t.Errorf("Expand returned for a length of %d instead of refusing it", length)
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

	data := spare([]byte("the message"))
	dataBefore := bytes.Clone(data)
	digest := crypto.Hash(data)
	tag := crypto.Mac(spare([]byte("key")), data)
	prk := crypto.Extract(spare([]byte("salt")), data)
	okm := crypto.Expand(prk, data, 48)
	if !bytes.Equal(data, dataBefore) {
		t.Errorf("a primitive changed its input from %x to %x", dataBefore, data)
	}
	for _, result := range [][]byte{digest, tag, prk, okm} {
		if len(result) != 0 && &result[0] == &data[0] {
			t.Errorf("a primitive returned a slice aliasing its input")
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
	windows := [][]byte{script, script[:32], script[32:64], script[64:96], script[:16], script[16:32]}
	for _, window := range windows {
		ordered := bytes.Clone(window)
		slices.Sort(ordered)
		if bytes.Equal(window, ordered) {
			t.Errorf("the window %x is already sorted, so a sorting reader is invisible in it", window)
		}
		slices.Reverse(ordered)
		if bytes.Equal(window, ordered) {
			t.Errorf("the window %x is sorted descending", window)
		}
		reversed := bytes.Clone(window)
		slices.Reverse(reversed)
		if bytes.Equal(window, reversed) {
			t.Errorf("the window %x reads the same backwards, so a reversing reader is invisible in it", window)
		}
		for shift := 1; shift < len(window); shift++ {
			rotated := append(bytes.Clone(window[shift:]), window[:shift]...)
			if bytes.Equal(window, rotated) {
				t.Errorf("the window %x equals itself rotated by %d", window, shift)
			}
		}
		if bytes.Equal(window, bytes.Repeat(window[:1], len(window))) {
			t.Errorf("the window %x is constant", window)
		}
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
	for _, length := range []int{32, 16, 1, 47} {
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

// The default constructor must not be deterministic. A provider that quietly took a fixed
// stream would pass every other test in this package and destroy every key in production.
func TestNewCryptoProviderDefaultsToCryptoRand(t *testing.T) {
	first := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	second := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	if bytes.Equal(first.Random(32), second.Random(32)) {
		t.Fatalf("two default providers produced the same random bytes")
	}
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
// concurrent use. Run under -race, which is what makes this mean anything.
func TestProviderIsSafeForConcurrentUse(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	key := bytes.Repeat([]byte{0x0f}, 32)
	nonce := make([]byte, 12)
	want := crypto.Hash([]byte("data"))

	var waitGroup sync.WaitGroup
	for i := 0; i < 32; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for j := 0; j < 64; j++ {
				if !bytes.Equal(crypto.Hash([]byte("data")), want) {
					t.Errorf("Hash disagreed with itself under concurrency")
					return
				}
				crypto.Mac(key, []byte("data"))
				crypto.Extract(key, []byte("ikm"))
				crypto.Expand(key, []byte("info"), 32)
				crypto.Random(32)
				if _, err := crypto.AeadSeal(key, nonce, nil, []byte("plaintext")); err != nil {
					t.Errorf("seal: %v", err)
					return
				}
			}
		}()
	}
	waitGroup.Wait()
}

// The methods tasks 12 to 16 complete must refuse to be called until they are, rather
// than returning a zero value. A stub returning nil, nil from HpkeOpen would compile,
// satisfy the interface, and be a total authentication bypass for anyone calling it in
// the meantime. This is the counterpart of TestProviderHasNoRemainingStubs in task 16:
// that one asserts the list is empty at the end of the wave, this one asserts that what
// is still on the list is loud.
func TestProviderStubsRefuseToBeCalled(t *testing.T) {
	crypto := mustProvider(t, CipherSuiteX25519ChaCha20Sha256Ed25519)
	for _, testCase := range []struct {
		name string
		call func()
	}{
		{name: "ExpandWithLabel", call: func() { crypto.ExpandWithLabel(nil, "label", nil, 32) }},
		{name: "DeriveSecret", call: func() { crypto.DeriveSecret(nil, "label") }},
		{name: "DeriveTreeSecret", call: func() { crypto.DeriveTreeSecret(nil, "label", 0, 32) }},
		{name: "SignWithLabel", call: func() { crypto.SignWithLabel(nil, "label", nil) }},
		{name: "VerifyWithLabel", call: func() { crypto.VerifyWithLabel(nil, "label", nil, nil) }},
		{name: "SignatureKeyPair", call: func() { crypto.SignatureKeyPair() }},
		{name: "HpkeSeal", call: func() { crypto.HpkeSeal(nil, nil, nil, nil) }},
		{name: "HpkeOpen", call: func() { crypto.HpkeOpen(nil, nil, nil, nil, nil) }},
		{name: "DeriveKeyPair", call: func() { crypto.DeriveKeyPair(nil) }},
	} {
		if recovered := recoveredPanic(testCase.call); recovered == nil {
			t.Errorf("%s returned instead of refusing; an unimplemented method must not answer", testCase.name)
		}
	}
}
