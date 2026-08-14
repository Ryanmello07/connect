// What the suite identifiers and the labelled kdf have to be, stated against RFC 9180's
// own published bytes rather than against this package's other half.
//
// A labelled kdf returns 32 well formed bytes for every wrong construction there is. Swap
// the salt and the ikm, drop the version label, leave out the two byte length prefix,
// transpose the kdf and aead code points — each one still extracts, still expands, still
// errors nowhere, and still hands back keys of exactly the right length that no other
// implementation will ever reproduce. So nothing here rests on a call having succeeded.
// Every claim about a derived byte is pinned to a value printed in RFC 9180 appendix A,
// and the round trips and length checks are only the frame around that.
//
// Both registered suites are carried because the collision named in hpke.go's file
// comment is invisible on one of them: 0x0001 is simultaneously the HKDF-SHA256 kdf and
// the AES-128-GCM aead, so on suite 0x0001 the two positions hold the same byte and a
// transposition changes nothing anyone could observe. On 0x0003 the aead is 0x0003 and
// the same transposition moves every derived byte in the vector. A single suite table
// would therefore be a table that cannot see the mistake this file exists to catch.
//
// The vectors stop where task 5 does. RFC 9180 publishes the key schedule inputs and
// outputs — shared_secret, key_schedule_context, secret, key, base_nonce,
// exporter_secret — and each of those is a labelled extract or expand away from the
// previous one, so the whole chain up to the aead is reachable with the four functions
// this task defines and no others. The aead itself, the sequence number and the context
// object are tasks 6 to 8, and the vendored corpus that replaces these transcriptions is
// task 9's.
//
// There is no general hex helper declared here. This package's one decoder is the interop
// harness's MustHex, which has not landed, so the single decode below is inlined against
// the day it does rather than becoming a second one with its own opinion about odd length
// input.
package mls

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// One base mode entry of RFC 9180 appendix A, as published: the hex is transcribed from
// the RFC text, and the fields are exactly those a labelled extract or expand consumes or
// produces. mode is not a field because base mode is the only mode this file implements
// and hpkeModeBase is the constant under test rather than an input.
//
// info is the RFC's own "Ode on a Grecian Urn" string. It is not empty on purpose: an
// empty info would make the info_hash extract indistinguishable from the psk_id_hash one
// beside it, and the two differ only in their label.
type rfc9180BaseVector struct {
	name               string
	suite              CipherSuite
	info               string
	skEm               string
	pkRm               string
	enc                string
	sharedSecret       string
	keyScheduleContext string
	secret             string
	key                string
	baseNonce          string
	exporterSecret     string
}

// The two appendix A entries whose kem, kdf and aead this package registers. A.1 is
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM and A.2 is the same with
// ChaCha20-Poly1305; the RFC's other entries name a kem or a mode that is not
// implemented here and would assert nothing.
var rfc9180BaseVectors = []rfc9180BaseVector{
	{
		name:               "rfc 9180 appendix a.1.1, aes-128-gcm",
		suite:              CipherSuiteX25519AesGcm128Sha256Ed25519,
		info:               "4f6465206f6e2061204772656369616e2055726e",
		skEm:               "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
		pkRm:               "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
		enc:                "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
		sharedSecret:       "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
		keyScheduleContext: "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449",
		secret:             "12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397",
		key:                "4531685d41d65f03dc48f6b8302c05b0",
		baseNonce:          "56d890e5accaaf011cff4b7d",
		exporterSecret:     "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8",
	},
	{
		name:               "rfc 9180 appendix a.2.1, chacha20-poly1305",
		suite:              CipherSuiteX25519ChaCha20Sha256Ed25519,
		info:               "4f6465206f6e2061204772656369616e2055726e",
		skEm:               "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
		pkRm:               "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
		enc:                "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
		sharedSecret:       "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
		keyScheduleContext: "00431df6cd95e11ff49d7013563baf7f11588c75a6611ee2a4404a49306ae4cfc5b69c5718a60cc5876c358d3f7fc31ddb598503f67be58ea1e798c0bb19eb9796",
		secret:             "5b9cd775e64b437a2335cf499361b2e0d5e444d5cb41a8a53336d8fe402282c6",
		key:                "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
		baseNonce:          "5c4d98150661b848853b547f",
		exporterSecret:     "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922",
	},
}

// One transcribed field, with a bad transcription fatal rather than an empty slice: an
// odd length or a stray character would otherwise silently turn a known answer into a
// comparison against nothing, which is the one way a table like this passes while
// asserting less than it says.
func decodeVectorField(t *testing.T, vectorName string, fieldName string, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("%s: %s is not hex: %v", vectorName, fieldName, err)
	}
	if len(decoded) == 0 {
		t.Fatalf("%s: %s decoded to nothing", vectorName, fieldName)
	}
	return decoded
}

// TestHpkeSuiteIds pins the two identifiers byte for byte against RFC 9180 section 5.1,
// written out as literals rather than rebuilt from the registry so this test disagrees
// with hpke.go when hpke.go changes. The chacha row is the load bearing one: it is the
// only place a kdf and aead transposition is visible, since the aes suite holds 0x0001
// in both positions.
func TestHpkeSuiteIds(t *testing.T) {
	chacha, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	if got, want := hpkeKemSuiteId(chacha), append([]byte("KEM"), 0x00, 0x20); !bytes.Equal(got, want) {
		t.Errorf("kem suite id = %x, want %x", got, want)
	}
	if got, want := hpkeSuiteId(chacha), append([]byte("HPKE"), 0x00, 0x20, 0x00, 0x01, 0x00, 0x03); !bytes.Equal(got, want) {
		t.Errorf("hpke suite id = %x, want %x", got, want)
	}

	aes, err := LookupSuite(CipherSuiteX25519AesGcm128Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	if got, want := hpkeSuiteId(aes), append([]byte("HPKE"), 0x00, 0x20, 0x00, 0x01, 0x00, 0x01); !bytes.Equal(got, want) {
		t.Errorf("aes hpke suite id = %x, want %x", got, want)
	}
}

// TestHpkeKemSuiteIdDerivesThePublishedSharedSecret is the kem suite id's only real
// exercise: the literal comparison above says what the bytes are, and this says they are
// the bytes RFC 9180 actually derived with. The chain is the whole of DHKEM Encap after
// the diffie-hellman — extract to eae_prk, expand to the shared secret over enc || pkRm —
// so a wrong prefix, a wrong label, a swapped salt or a missing length prefix all land on
// a shared secret the RFC never printed.
//
// The diffie-hellman itself comes from X25519DH, which crypto_x25519_test.go already pins
// against RFC 7748, so a failure here is a kdf failure rather than a curve one.
func TestHpkeKemSuiteIdDerivesThePublishedSharedSecret(t *testing.T) {
	if len(rfc9180BaseVectors) == 0 {
		t.Fatal("the vector table is empty, so the loop below asserts nothing")
	}
	for _, vector := range rfc9180BaseVectors {
		params, err := LookupSuite(vector.suite)
		if err != nil {
			t.Fatalf("%s: LookupSuite: %v", vector.name, err)
		}
		priv, err := X25519PrivateKey(decodeVectorField(t, vector.name, "skEm", vector.skEm))
		if err != nil {
			t.Fatalf("%s: skEm: %v", vector.name, err)
		}
		pkRm := decodeVectorField(t, vector.name, "pkRm", vector.pkRm)
		pub, err := X25519PublicKey(pkRm)
		if err != nil {
			t.Fatalf("%s: pkRm: %v", vector.name, err)
		}
		dh, err := X25519DH(priv, pub)
		if err != nil {
			t.Fatalf("%s: dh: %v", vector.name, err)
		}
		kemSuiteId := hpkeKemSuiteId(params)
		kemContext := append(decodeVectorField(t, vector.name, "enc", vector.enc), pkRm...)
		eaePrk := hpkeLabeledExtract(kemSuiteId, nil, "eae_prk", dh)
		got, err := hpkeLabeledExpand(kemSuiteId, eaePrk, "shared_secret", kemContext, params.Nsecret)
		if err != nil {
			t.Fatalf("%s: shared_secret: %v", vector.name, err)
		}
		want := decodeVectorField(t, vector.name, "shared_secret", vector.sharedSecret)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: shared_secret = %x, want %x", vector.name, got, want)
		}
	}
}

// TestHpkeLabeledExtractKat pins the extract half against the two published values it can
// reach on its own. The key schedule context is the concatenation of two extracts that
// differ only in their label and their ikm, so a label that was dropped or a version
// prefix that moved collapses them onto each other; and the secret is an extract whose
// salt is the 32 byte shared secret and whose ikm is empty, which is the one shape where
// swapping crypto/hkdf's two arguments cannot be mistaken for anything else.
func TestHpkeLabeledExtractKat(t *testing.T) {
	if len(rfc9180BaseVectors) == 0 {
		t.Fatal("the vector table is empty, so the loop below asserts nothing")
	}
	for _, vector := range rfc9180BaseVectors {
		params, err := LookupSuite(vector.suite)
		if err != nil {
			t.Fatalf("%s: LookupSuite: %v", vector.name, err)
		}
		suiteId := hpkeSuiteId(params)
		pskIdHash := hpkeLabeledExtract(suiteId, nil, "psk_id_hash", nil)
		infoHash := hpkeLabeledExtract(suiteId, nil, "info_hash", decodeVectorField(t, vector.name, "info", vector.info))
		context := append([]byte{hpkeModeBase}, pskIdHash...)
		context = append(context, infoHash...)
		wantContext := decodeVectorField(t, vector.name, "key_schedule_context", vector.keyScheduleContext)
		if !bytes.Equal(context, wantContext) {
			t.Errorf("%s: key_schedule_context = %x, want %x", vector.name, context, wantContext)
		}

		sharedSecret := decodeVectorField(t, vector.name, "shared_secret", vector.sharedSecret)
		secret := hpkeLabeledExtract(suiteId, sharedSecret, "secret", nil)
		wantSecret := decodeVectorField(t, vector.name, "secret", vector.secret)
		if !bytes.Equal(secret, wantSecret) {
			t.Errorf("%s: secret = %x, want %x", vector.name, secret, wantSecret)
		}
	}
}

// TestHpkeLabeledExpandKat pins the expand half the same way, from the published secret
// and key schedule context rather than from the ones derived above, so a break in the
// extract half cannot travel here and be reported twice.
//
// The three outputs are 16 or 32, 12 and 32 bytes, and the length is both an argument and
// the first two bytes of the preimage. That is what makes the two byte prefix testable at
// all: an implementation that omitted it still returns the right number of bytes every
// time, and only differs in what those bytes are — differently for each of the three
// lengths here, and differently again between the two suites, whose keys are 16 and 32
// bytes from the same construction.
func TestHpkeLabeledExpandKat(t *testing.T) {
	if len(rfc9180BaseVectors) == 0 {
		t.Fatal("the vector table is empty, so the loop below asserts nothing")
	}
	for _, vector := range rfc9180BaseVectors {
		params, err := LookupSuite(vector.suite)
		if err != nil {
			t.Fatalf("%s: LookupSuite: %v", vector.name, err)
		}
		suiteId := hpkeSuiteId(params)
		secret := decodeVectorField(t, vector.name, "secret", vector.secret)
		context := decodeVectorField(t, vector.name, "key_schedule_context", vector.keyScheduleContext)
		expansions := []struct {
			field  string
			label  string
			length int
			want   string
		}{
			{field: "key", label: "key", length: params.Nk, want: vector.key},
			{field: "base_nonce", label: "base_nonce", length: params.Nn, want: vector.baseNonce},
			{field: "exporter_secret", label: "exp", length: params.Nh, want: vector.exporterSecret},
		}
		for _, expansion := range expansions {
			got, err := hpkeLabeledExpand(suiteId, secret, expansion.label, context, expansion.length)
			if err != nil {
				t.Fatalf("%s: %s: %v", vector.name, expansion.field, err)
			}
			want := decodeVectorField(t, vector.name, expansion.field, expansion.want)
			if len(want) != expansion.length {
				t.Fatalf("%s: %s is %d published bytes, the suite says %d", vector.name, expansion.field, len(want), expansion.length)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s: %s = %x, want %x", vector.name, expansion.field, got, want)
			}
		}
	}
}

// TestHpkeLabeledExtractTreatsNilAndEmptySaltAlike states the equivalence RFC 9180 relies
// on when it writes LabeledExtract("", ...). crypto/hkdf substitutes a zero filled block
// for a nil salt and HMAC zero pads an empty key to the same block, so the two agree —
// but that is the standard library's behaviour rather than this package's, and a wrapper
// that substituted a default salt of its own for nil would break it silently.
func TestHpkeLabeledExtractTreatsNilAndEmptySaltAlike(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	suiteId := hpkeKemSuiteId(params)
	if len(rfc9180BaseVectors) != 2 {
		t.Fatalf("the vector table holds %d entries, want the two appendix a rows", len(rfc9180BaseVectors))
	}
	chacha := rfc9180BaseVectors[1]
	ikm := decodeVectorField(t, chacha.name, "shared_secret", chacha.sharedSecret)
	fromNil := hpkeLabeledExtract(suiteId, nil, "eae_prk", ikm)
	fromEmpty := hpkeLabeledExtract(suiteId, []byte{}, "eae_prk", ikm)
	if !bytes.Equal(fromNil, fromEmpty) {
		t.Fatalf("nil and empty salt disagree: %x vs %x", fromNil, fromEmpty)
	}
	if len(fromNil) != hpkeKdfNh {
		t.Fatalf("prk is %d bytes, want %d", len(fromNil), hpkeKdfNh)
	}
}

// TestHpkeLabeledExpandRejectsUnrepresentableLengths covers the lengths that must not
// produce a key. Over 255*Nh there is nothing HKDF-Expand can return. Below zero
// crypto/hkdf.Expand does not return anything at all: its fips140 body opens with
// out := make([]byte, 0, keyLen) and a negative cap is "makeslice: cap out of range", so
// the refusal asserted here is what stands between a caller supplied length and a dead
// process — task 8's Export takes that length from a caller.
//
// The two lengths past 65535 are subsumed by the 8160 ceiling as the constants stand
// today; they are carried against a suite whose Nh would lift the ceiling past what the
// two byte I2OSP prefix can encode, which is the only world where they assert something
// the ceiling does not. The accepting case is asserted beside all of them, because a
// function hardwired to refuse everything satisfies the refusals on its own.
func TestHpkeLabeledExpandRejectsUnrepresentableLengths(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	suiteId := hpkeSuiteId(params)
	prk := make([]byte, hpkeKdfNh)
	for _, length := range []int{-1, hpkeMaxExpandLength + 1, 1 << 16, 1<<16 + params.Nk} {
		out, err := hpkeLabeledExpand(suiteId, prk, "key", nil, length)
		if !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("expand of %d bytes returned error %v, want ErrBadKeyLength", length, err)
		}
		if out != nil {
			t.Errorf("expand of %d bytes refused and returned %d bytes anyway", length, len(out))
		}
	}
	for _, length := range []int{0, 1, params.Nn, params.Nk, hpkeMaxExpandLength} {
		out, err := hpkeLabeledExpand(suiteId, prk, "key", nil, length)
		if err != nil {
			t.Fatalf("expand rejected %d bytes: %v", length, err)
		}
		if len(out) != length {
			t.Fatalf("expand of %d bytes returned %d", length, len(out))
		}
	}
}

// TestHpkeExpandCeilingIsTheLibrarysOwnBoundary pins hpkeMaxExpandLength to something
// other than itself. Every assertion about the ceiling in the refusal test above is
// written as hpkeMaxExpandLength or hpkeMaxExpandLength+1, so together they say only
// "the guard fires just above wherever the constant sits" — which is true of any value
// the constant could hold, and measurably so: setting it to 1*hpkeKdfNh, a 255 fold
// under estimate, leaves the whole package green, as does 254*hpkeKdfNh. Only 256*
// failed, and only because crypto/hkdf enforces its own limit.
//
// So the constant is asserted here against the library it exists to describe rather than
// against the guard that reads it. RFC 5869 section 2.3 stops the expansion counter at
// 255 and crypto/hkdf implements exactly that, so 255*Nh is the largest length the kdf
// will serve and 255*Nh+1 is the smallest it refuses. A ceiling that drifted tighter
// fails on the reject half, because the kdf still serves that length; one that drifted
// looser fails on the accept half, because the kdf will not serve it.
//
// Calling hkdf here is allowed and was checked against crypto_forbidden_test.go rather
// than assumed: the confinement gate's needle is hkdf.Extract( and not hkdf.Expand(, and
// it runs over productionSources, which drops every _test.go file.
func TestHpkeExpandCeilingIsTheLibrarysOwnBoundary(t *testing.T) {
	prk := make([]byte, hpkeKdfNh)
	out, err := hkdf.Expand(sha256.New, prk, "ceiling", hpkeMaxExpandLength)
	if err != nil {
		t.Errorf("the kdf refused %d bytes, so the ceiling sits above what it will serve: %v", hpkeMaxExpandLength, err)
	} else if len(out) != hpkeMaxExpandLength {
		t.Errorf("the kdf returned %d bytes for a request of %d", len(out), hpkeMaxExpandLength)
	}
	if _, err := hkdf.Expand(sha256.New, prk, "ceiling", hpkeMaxExpandLength+1); err == nil {
		t.Errorf("the kdf served %d bytes, so the ceiling sits below what it will serve", hpkeMaxExpandLength+1)
	}
}

// TestHpkeExpandCeilingMatchesTheRegistry keeps the constant the guard above is written
// against from drifting away from the suites it guards. hpkeMaxExpandLength is 255 times
// the kdf output size, and it is stated once for HMAC-SHA256 rather than read per suite;
// a third suite whose Nh was not 32 would make it wrong for that suite without changing a
// line of hpke.go.
//
// Both halves are needed and neither implies the other. The Nh check catches a suite that
// arrived with a different kdf output; the ceiling check catches the constant being
// restated as anything but 255 times it — which is what this test was named for and did
// not do, since its body mentioned only Nh.
func TestHpkeExpandCeilingMatchesTheRegistry(t *testing.T) {
	suites := Suites()
	if len(suites) == 0 {
		t.Fatal("the registry is empty, so the loop below asserts nothing")
	}
	for _, suite := range suites {
		params, err := LookupSuite(suite)
		if err != nil {
			t.Fatalf("LookupSuite %#04x: %v", uint16(suite), err)
		}
		if params.Nh != hpkeKdfNh {
			t.Errorf("suite %#04x has Nh %d, the expand ceiling assumes %d", uint16(suite), params.Nh, hpkeKdfNh)
		}
		if hpkeMaxExpandLength != 255*params.Nh {
			t.Errorf("suite %#04x has Nh %d, so its expand ceiling is %d, but the constant is %d", uint16(suite), params.Nh, 255*params.Nh, hpkeMaxExpandLength)
		}
	}
}
