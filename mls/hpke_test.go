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
// The vectors stop where task 6 does. RFC 9180 publishes the key schedule inputs and
// outputs — shared_secret, key_schedule_context, secret, key, base_nonce,
// exporter_secret — and each of those is a labelled extract or expand away from the
// previous one, so the whole chain up to the aead is reachable with the four labelled kdf
// functions and no others; the kem key pairs, the encapsulation and the decapsulation are
// published beside them and are what the second half of this file pins. The aead itself,
// the sequence number and the context object are tasks 7 and 8, and the vendored corpus
// that replaces these transcriptions is task 9's.
//
// Nothing about DHKEM is reachable by round trip. Encap and Decap that are wrong in the
// same way agree with each other perfectly: transpose enc and pkRm in the kem context on
// both sides, write the ephemeral key into the recipient's slot on both sides, respell
// eae_prk, or return the raw diffie-hellman output in place of the extract-and-expand, and
// every one of those still produces a 32 byte secret both parties reach. Each was applied
// to hpke.go and left the round trip, the length checks and the determinism checks green.
// So the encap and decap tests below assert against published bytes, and the round trip is
// only there to say the two entry points are not separately correct against nothing.
//
// There is no general hex helper declared here. This package's one decoder is the interop
// harness's MustHex, which has not landed, so the single decode below is inlined against
// the day it does rather than becoming a second one with its own opinion about odd length
// input.
package mls

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// One base mode entry of RFC 9180 appendix A, as published, with the fields exactly those
// a labelled extract or expand, a key pair derivation, an encapsulation or a decapsulation
// consumes or produces. mode is not a field because base mode is the only mode this file
// implements and hpkeModeBase is the constant under test rather than an input.
//
// Two provenances, stated per field because a known answer test is worth only its sourcing
// and a value taken from the implementation it checks proves nothing. info, skEm, pkRm,
// enc, shared_secret, key_schedule_context, secret, key, base_nonce and exporter_secret
// were transcribed from the RFC 9180 appendix A text by task 5. ikmE, ikmR and skRm — the
// three task 6 needs and appendix A prints but task 5 had no use for — were read out of
// the pinned toolchain's own vendored copy of the same corpus, at
// GOROOT/src/crypto/hpke/testdata/rfc9180.json, which is the cfrg published
// test-vectors.json filtered to the base mode entries.
//
// The two sources overlap on info, pkRm and enc and agree on all three, so each checks the
// other's transcription. Beyond that the table is self checking in a way a hand copied
// blob is not: ikmE has to derive to the skEm the RFC printed and to the enc it printed,
// ikmR to skRm and pkRm, and skRm with enc to the shared_secret that task 5 already pinned
// through an independent path. A wrong character in any of the three new fields fails
// against a value that was already in the table rather than being absorbed.
//
// info is the RFC's own "Ode on a Grecian Urn" string. It is not empty on purpose: an
// empty info would make the info_hash extract indistinguishable from the psk_id_hash one
// beside it, and the two differ only in their label.
type rfc9180BaseVector struct {
	name               string
	suite              CipherSuite
	info               string
	ikmE               string
	skEm               string
	ikmR               string
	skRm               string
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
		ikmE:               "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
		skEm:               "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
		ikmR:               "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037",
		skRm:               "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
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
		ikmE:               "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
		skEm:               "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
		ikmR:               "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
		skRm:               "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
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

// The guard every known answer loop below opens with. A table that lost a row is not an
// empty table, and only the empty case was ever refused — so until this existed, dropping
// either appendix A row left every task 6 known answer green, and the only thing that
// failed was a task 5 salt test that happened to index the second row.
//
// That is the wrong defence for the claim this file makes. The file comment above rests on
// carrying both registered suites, because RFC 9180 gives HKDF-SHA256 the kdf code point
// 0x0001 and AES-128-GCM the aead code point 0x0001: on the aes suite a kdf/aead
// transposition moves no byte anyone can see, and the chacha suite at 0x0003 is the only
// place it shows. A one row table is therefore a table that cannot see the mistake these
// vectors exist to catch, whichever row is left.
//
// It asserts a row per registered suite in the registry's own order rather than a literal
// two, so a third suite registered without a vector fails here as well, and the loops
// below and the test that indexes rfc9180BaseVectors[1] by hand agree about which row is
// which for a stated reason.
func requireAVectorPerRegisteredSuite(t *testing.T) {
	t.Helper()
	suites := Suites()
	if len(rfc9180BaseVectors) != len(suites) {
		t.Fatalf("the vector table holds %d rows for %d registered suites, so a suite goes unpinned", len(rfc9180BaseVectors), len(suites))
	}
	for i, suite := range suites {
		if rfc9180BaseVectors[i].suite != suite {
			t.Fatalf("vector row %d is for suite %#04x, want %#04x", i, uint16(rfc9180BaseVectors[i].suite), uint16(suite))
		}
	}
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
	requireAVectorPerRegisteredSuite(t)
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
	requireAVectorPerRegisteredSuite(t)
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
	requireAVectorPerRegisteredSuite(t)
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
	requireAVectorPerRegisteredSuite(t)
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

// TestHpkeDeriveKeyPairMatchesThePublishedKeyPairs is the known answer for DeriveKeyPair,
// and the reason the ikm fields were added to the table. Determinism, the sizes and the
// sensitivity to the ikm are all satisfied by any deterministic function of the input, so
// none of them can tell the RFC's derivation from a plausible neighbour: dropping the
// dkp_prk label, respelling it, expanding under "key" instead of "sk", or deriving under
// the whole suite id instead of the kem one each leave a well formed 32 byte scalar and a
// public key on the curve. Only the published pair separates them.
//
// Both key pairs of each vector are derived, because they exercise different halves of
// what follows: skEm is the input to encapsulation and skRm to decapsulation, and a
// derivation that was right for one and wrong for the other is exactly the shape a single
// row would miss. pkEm is checked as enc, since RFC 9180 section 4.1 defines the
// encapsulated key of a DHKEM as SerializePublicKey(pkE) and the appendix prints the two
// as the same bytes.
func TestHpkeDeriveKeyPairMatchesThePublishedKeyPairs(t *testing.T) {
	requireAVectorPerRegisteredSuite(t)
	for _, vector := range rfc9180BaseVectors {
		params, err := LookupSuite(vector.suite)
		if err != nil {
			t.Fatalf("%s: LookupSuite: %v", vector.name, err)
		}
		derivations := []struct {
			role       string
			ikm        string
			privateKey string
			publicKey  string
		}{
			{role: "ephemeral", ikm: vector.ikmE, privateKey: vector.skEm, publicKey: vector.enc},
			{role: "recipient", ikm: vector.ikmR, privateKey: vector.skRm, publicKey: vector.pkRm},
		}
		for _, derivation := range derivations {
			ikm := decodeVectorField(t, vector.name, derivation.role+" ikm", derivation.ikm)
			priv, pub, err := HpkeDeriveKeyPair(params, ikm)
			if err != nil {
				t.Fatalf("%s: %s: HpkeDeriveKeyPair: %v", vector.name, derivation.role, err)
			}
			wantPriv := decodeVectorField(t, vector.name, derivation.role+" private key", derivation.privateKey)
			if !bytes.Equal(priv, wantPriv) {
				t.Errorf("%s: %s private key = %x, want %x", vector.name, derivation.role, priv, wantPriv)
			}
			wantPub := decodeVectorField(t, vector.name, derivation.role+" public key", derivation.publicKey)
			if !bytes.Equal(pub, wantPub) {
				t.Errorf("%s: %s public key = %x, want %x", vector.name, derivation.role, pub, wantPub)
			}
		}
	}
}

// TestHpkeDeriveKeyPairIsDeterministic states the properties the known answer above cannot
// reach on its own: that a second call on the same ikm returns the same pair rather than
// reading entropy somewhere, that the lengths are the ones the suite fixes, and that the
// ikm is actually consumed. On its own this test is satisfied by any deterministic
// function, which is why it is written beside the vectors rather than instead of them.
func TestHpkeDeriveKeyPairIsDeterministic(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	ikm := bytes.Repeat([]byte{0x42}, 32)
	priv1, pub1, err := HpkeDeriveKeyPair(params, ikm)
	if err != nil {
		t.Fatalf("derive 1: %v", err)
	}
	priv2, pub2, err := HpkeDeriveKeyPair(params, ikm)
	if err != nil {
		t.Fatalf("derive 2: %v", err)
	}
	if !bytes.Equal(priv1, priv2) || !bytes.Equal(pub1, pub2) {
		t.Fatalf("derive is not deterministic")
	}
	if len(priv1) != params.Nsk || len(pub1) != params.Npk {
		t.Fatalf("sizes are %d/%d, want %d/%d", len(priv1), len(pub1), params.Nsk, params.Npk)
	}
	_, pub3, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		t.Fatalf("derive 3: %v", err)
	}
	if bytes.Equal(pub1, pub3) {
		t.Fatalf("different ikm produced the same public key")
	}
}

// TestHpkeEncapMatchesThePublishedEncapsulation is the assertion this task turns on. Both
// entry points are driven from the vector's own ephemeral scalar and both have to produce
// the shared secret and the enc RFC 9180 printed.
//
// The randomized one is included rather than assumed equivalent because the plan's own test
// for that only checked the deterministic one against a key pair it derived itself, which
// is true of any pair of functions that return their argument. Driving hpkeEncap from a
// reader scripted with skEm reaches the same published bytes through the code path
// production actually uses, and the equality check afterwards is then a statement about two
// things that were each separately pinned.
//
// What this catches that the round trip cannot: kem_context transposed to pkRm concatenated
// with enc, the recipient's key replaced by the ephemeral one in the second slot, eae_prk or
// shared_secret respelled or dropped, the extract-and-expand skipped so the raw
// diffie-hellman output is returned, and the kem suite id swapped for the whole suite id.
// All six were applied to hpke.go and all six survive every non vector test in this file.
func TestHpkeEncapMatchesThePublishedEncapsulation(t *testing.T) {
	requireAVectorPerRegisteredSuite(t)
	for _, vector := range rfc9180BaseVectors {
		params, err := LookupSuite(vector.suite)
		if err != nil {
			t.Fatalf("%s: LookupSuite: %v", vector.name, err)
		}
		skEm := decodeVectorField(t, vector.name, "skEm", vector.skEm)
		pkRm := HpkePublicKey(decodeVectorField(t, vector.name, "pkRm", vector.pkRm))
		wantSecret := decodeVectorField(t, vector.name, "shared_secret", vector.sharedSecret)
		wantEnc := decodeVectorField(t, vector.name, "enc", vector.enc)

		secret, enc, err := hpkeEncapDeterministic(params, pkRm, HpkePrivateKey(skEm))
		if err != nil {
			t.Fatalf("%s: hpkeEncapDeterministic: %v", vector.name, err)
		}
		if !bytes.Equal(secret, wantSecret) {
			t.Errorf("%s: deterministic shared_secret = %x, want %x", vector.name, secret, wantSecret)
		}
		if !bytes.Equal(enc, wantEnc) {
			t.Errorf("%s: deterministic enc = %x, want %x", vector.name, enc, wantEnc)
		}

		// the same encapsulation through the randomized entry point, whose ephemeral
		// scalar is whatever its reader supplies — which is what makes the vector
		// reachable from the function production calls
		randomizedSecret, randomizedEnc, err := hpkeEncap(bytes.NewReader(skEm), params, pkRm)
		if err != nil {
			t.Fatalf("%s: hpkeEncap: %v", vector.name, err)
		}
		if !bytes.Equal(randomizedSecret, wantSecret) {
			t.Errorf("%s: randomized shared_secret = %x, want %x", vector.name, randomizedSecret, wantSecret)
		}
		if !bytes.Equal(randomizedEnc, wantEnc) {
			t.Errorf("%s: randomized enc = %x, want %x", vector.name, randomizedEnc, wantEnc)
		}
	}
}

// TestHpkeDecapMatchesThePublishedSharedSecret is the other side, and it is not implied by
// the encap vectors. Decap never sees pkRm on the wire — it recomputes that half of the kem
// context from the private key it holds — so it is a second implementation of the same
// concatenation, with its own opportunity to put its own key first, and the round trip
// cannot see the difference because it would agree with an encap transposed to match.
func TestHpkeDecapMatchesThePublishedSharedSecret(t *testing.T) {
	requireAVectorPerRegisteredSuite(t)
	for _, vector := range rfc9180BaseVectors {
		params, err := LookupSuite(vector.suite)
		if err != nil {
			t.Fatalf("%s: LookupSuite: %v", vector.name, err)
		}
		skRm := HpkePrivateKey(decodeVectorField(t, vector.name, "skRm", vector.skRm))
		enc := decodeVectorField(t, vector.name, "enc", vector.enc)
		secret, err := hpkeDecap(params, skRm, enc)
		if err != nil {
			t.Fatalf("%s: hpkeDecap: %v", vector.name, err)
		}
		want := decodeVectorField(t, vector.name, "shared_secret", vector.sharedSecret)
		if !bytes.Equal(secret, want) {
			t.Errorf("%s: shared_secret = %x, want %x", vector.name, secret, want)
		}
	}
}

// TestHpkeEncapDecapAgree is the frame around the vectors rather than an assertion in its
// own right: it says the two entry points are the same computation over a key pair neither
// vector supplies, across both registered suites and with a real entropy source. Every
// mutation listed in this file's comment passes it. What it does add is the sensitivity
// check at the end — a decapsulation under a different private key has to reach different
// bytes, which is the one thing here that a constant returning kem would fail.
func TestHpkeEncapDecapAgree(t *testing.T) {
	suites := Suites()
	if len(suites) == 0 {
		t.Fatal("the registry is empty, so the loop below asserts nothing")
	}
	for _, suite := range suites {
		params, err := LookupSuite(suite)
		if err != nil {
			t.Fatalf("LookupSuite %#04x: %v", uint16(suite), err)
		}
		priv, pub, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x01}, 32))
		if err != nil {
			t.Fatalf("derive: %v", err)
		}
		sharedSecret, kemOutput, err := hpkeEncap(rand.Reader, params, pub)
		if err != nil {
			t.Fatalf("encap: %v", err)
		}
		if len(kemOutput) != params.Nenc {
			t.Fatalf("kem output is %d bytes, want %d", len(kemOutput), params.Nenc)
		}
		if len(sharedSecret) != params.Nsecret {
			t.Fatalf("shared secret is %d bytes, want %d", len(sharedSecret), params.Nsecret)
		}
		back, err := hpkeDecap(params, priv, kemOutput)
		if err != nil {
			t.Fatalf("decap: %v", err)
		}
		if !bytes.Equal(sharedSecret, back) {
			t.Fatalf("suite %#04x: encap and decap disagree", uint16(suite))
		}
		strangerPriv, _, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x02}, 32))
		if err != nil {
			t.Fatalf("derive a stranger: %v", err)
		}
		// DHKEM does not authenticate the recipient, so the wrong key is not an error;
		// it is a different secret, and a kem that ignored its inputs would be caught
		// here and nowhere else in this test
		stranger, err := hpkeDecap(params, strangerPriv, kemOutput)
		if err != nil {
			t.Fatalf("decap under a stranger's key: %v", err)
		}
		if bytes.Equal(sharedSecret, stranger) {
			t.Fatalf("suite %#04x: a different private key reached the same secret %x", uint16(suite), stranger)
		}
	}
}

// TestHpkeEncapDeterministicMatchesEncap states the equivalence the vector gate depends on,
// over an ephemeral key that is not a published one: task 9 drives encapsulation through
// hpkeEncapDeterministic, so that entry point has to be the computation hpkeEncap performs
// rather than a second one written for the tests. The reader is scripted with the ephemeral
// scalar, which is the only way to hold the two sides to the same key.
//
// The plan's version of this test compared nothing: it checked that the deterministic
// encapsulation's kem output was the ephemeral public key and that the secret had the right
// length, and never called hpkeEncap at all, so the name was the whole of the claim.
func TestHpkeEncapDeterministicMatchesEncap(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	_, pub, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x03}, 32))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	ephemeralPriv, ephemeralPub, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x04}, 32))
	if err != nil {
		t.Fatalf("derive ephemeral: %v", err)
	}
	sharedSecret, kemOutput, err := hpkeEncapDeterministic(params, pub, ephemeralPriv)
	if err != nil {
		t.Fatalf("encap deterministic: %v", err)
	}
	if !bytes.Equal(kemOutput, ephemeralPub) {
		t.Fatalf("kem output %x is not the ephemeral public key %x", kemOutput, ephemeralPub)
	}
	if len(sharedSecret) != params.Nsecret {
		t.Fatalf("shared secret is %d bytes, want %d", len(sharedSecret), params.Nsecret)
	}
	randomizedSecret, randomizedKemOutput, err := hpkeEncap(bytes.NewReader(ephemeralPriv), params, pub)
	if err != nil {
		t.Fatalf("encap from a scripted reader: %v", err)
	}
	if !bytes.Equal(randomizedSecret, sharedSecret) {
		t.Fatalf("the two entry points disagree on the secret: %x vs %x", randomizedSecret, sharedSecret)
	}
	if !bytes.Equal(randomizedKemOutput, kemOutput) {
		t.Fatalf("the two entry points disagree on the kem output: %x vs %x", randomizedKemOutput, kemOutput)
	}
}

// TestHpkeDecapRejectsWrongLengths covers the lengths that must not reach the curve. The
// two sentinels are distinguished on purpose: a kem output is a peer's bytes and a private
// key of the wrong length is this process's own bug, and a caller triaging the two reads
// the wrong answer if they collapse. The accepting case is asserted beside them because a
// function hardwired to refuse everything satisfies every refusal on its own.
//
// The case where both lengths are wrong is asserted too, because the two loops below leave
// it free: each holds one length right, so neither can see which check runs first. hpkeDecap's
// own comment states a precedence — the peer's bytes are reported ahead of the local bug —
// and an order nothing pins is an order a later edit reverses without a failing test.
func TestHpkeDecapRejectsWrongLengths(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	priv, _, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x02}, 32))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	for _, n := range []int{0, 31, 33, 1024} {
		secret, err := hpkeDecap(params, priv, make([]byte, n))
		if !errors.Is(err, ErrBadKemOutput) {
			t.Errorf("decap(%d bytes) error = %v, want ErrBadKemOutput", n, err)
		}
		if secret != nil {
			t.Errorf("decap(%d bytes) refused and returned %d bytes anyway", n, len(secret))
		}
	}
	for _, n := range []int{0, 31, 33, 64} {
		secret, err := hpkeDecap(params, make(HpkePrivateKey, n), make([]byte, params.Nenc))
		if !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("decap with a %d byte private key error = %v, want ErrBadKeyLength", n, err)
		}
		if secret != nil {
			t.Errorf("decap with a %d byte private key refused and returned %d bytes anyway", n, len(secret))
		}
	}
	bothWrong, err := hpkeDecap(params, make(HpkePrivateKey, 31), make([]byte, 31))
	if !errors.Is(err, ErrBadKemOutput) {
		t.Errorf("decap with both lengths wrong error = %v, want ErrBadKemOutput", err)
	}
	if bothWrong != nil {
		t.Errorf("decap with both lengths wrong refused and returned %d bytes anyway", len(bothWrong))
	}
	_, kemOutput, err := hpkeEncap(rand.Reader, params, mustDeriveHpkePublicKey(t, params, 0x02))
	if err != nil {
		t.Fatalf("encap: %v", err)
	}
	if _, err := hpkeDecap(params, priv, kemOutput); err != nil {
		t.Fatalf("decap refused a well formed kem output: %v", err)
	}
}

// TestHpkeEncapRejectsWrongLengths is the same statement on the other side, and it needs
// its own test because the two length checks there guard different arguments: a recipient
// key off the wire and an ephemeral scalar the caller chose.
func TestHpkeEncapRejectsWrongLengths(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	pub := mustDeriveHpkePublicKey(t, params, 0x05)
	ephemeral := HpkePrivateKey(bytes.Repeat([]byte{0x06}, params.Nsk))
	for _, n := range []int{0, 31, 33, 64} {
		secret, enc, err := hpkeEncapDeterministic(params, make(HpkePublicKey, n), ephemeral)
		if !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("encap to a %d byte public key error = %v, want ErrBadKeyLength", n, err)
		}
		if secret != nil || enc != nil {
			t.Errorf("encap to a %d byte public key refused and returned %d/%d bytes anyway", n, len(secret), len(enc))
		}
		secret, enc, err = hpkeEncapDeterministic(params, pub, make(HpkePrivateKey, n))
		if !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("encap from a %d byte ephemeral scalar error = %v, want ErrBadKeyLength", n, err)
		}
		if secret != nil || enc != nil {
			t.Errorf("encap from a %d byte ephemeral scalar refused and returned %d/%d bytes anyway", n, len(secret), len(enc))
		}
	}
	if _, _, err := hpkeEncapDeterministic(params, pub, ephemeral); err != nil {
		t.Fatalf("encap refused well formed keys: %v", err)
	}
}

// TestHpkeKemReadsTheFieldItNames is the assertion the two tests above cannot make. Every
// length they check comes from a registered suite, and the registry gives Nh, Nsecret,
// Nenc, Npk, Nsk, NsigPub and NsigPriv the same 32 in both of its entries — so a function
// that read a neighbouring field instead of the one RFC 9180 names would satisfy every
// vector, every round trip and every refusal in this file. Seven fields holding one value
// are seven names for the same assertion. Nk, Nn and Nt are not in that set: the registry
// gives them 16 or 32, 12 and 16, so a kem gate that read one of those is already refused
// by the appendix A rows above and needs nothing here.
//
// Separating them does not need a registered suite, which is the reason this is testable
// at all. None of the four kem entry points consults the registry: each reads the
// *SuiteParams its caller hands it, and LookupSuite already returns a fresh copy rather
// than the registry's own entry. So the probes below are handed a SuiteParams whose length
// fields disagree, and such a value does not have to be registered, implementable or even
// coherent — nothing is derived from it but the length under test.
//
// The keys handed to each probe are well formed, so a probe that fails says the length
// gate did not fire rather than that some later gate fired in its place: a kem that drops
// or misdirects one of these checks reaches the curve and succeeds, and succeeding is what
// each assertion below denies.
//
// hpke.go reads a length in six places and all six are covered here — the Nsecret the
// shared secret expands to, the Nsk DeriveKeyPair expands to, and the four gates encap and
// decap open with. The two scalar gates need a probe of their own rather than riding on
// the recipient key one: under a suite that widens Npk, a scalar gate that wrongly read
// Npk refuses exactly what the right one refuses, so widening Nsk instead is what tells
// them apart.
func TestHpkeKemReadsTheFieldItNames(t *testing.T) {
	registered, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	priv, pub, err := HpkeDeriveKeyPair(registered, bytes.Repeat([]byte{0x0e}, 32))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	ephemeral := HpkePrivateKey(bytes.Repeat([]byte{0x0f}, registered.Nsk))
	_, kemOutput, err := hpkeEncapDeterministic(registered, pub, ephemeral)
	if err != nil {
		t.Fatalf("encap: %v", err)
	}

	// the shared secret expands to Nsecret, not to any of the lengths beside it
	wideNsecret := hpkeFieldProbeParams(32)
	wideNsecret.Nsecret = 48
	secret, err := hpkeExtractAndExpand(wideNsecret, make([]byte, 32), make([]byte, 64))
	if err != nil {
		t.Fatalf("extract and expand under Nsecret 48: %v", err)
	}
	if len(secret) != 48 {
		t.Errorf("shared secret is %d bytes under a suite whose Nsecret is 48 and whose every other length is 32, want 48", len(secret))
	}

	// the derived scalar expands to Nsk, not to any of the lengths around it. This probe
	// runs the other way round — narrow where the others are wide — because a derivation
	// has no refusal to assert: what says the right field was read is that the key pair
	// came out usable, and only the right field is a length x25519 accepts.
	narrowNsk := hpkeFieldProbeParams(48)
	narrowNsk.Nsk = 32
	probePriv, probePub, err := HpkeDeriveKeyPair(narrowNsk, bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatalf("derive under a suite whose only 32 byte length is Nsk: %v", err)
	}
	if len(probePriv) != 32 || len(probePub) != 32 {
		t.Errorf("derived %d/%d bytes under Nsk 32, want 32/32", len(probePriv), len(probePub))
	}

	// encap gates the recipient key on Npk, and gates it itself rather than leaving the
	// refusal to X25519PublicKey, whose own 32 byte length check would accept this key
	wideNpk := hpkeFieldProbeParams(32)
	wideNpk.Npk = 48
	if gotSecret, gotEnc, err := hpkeEncapDeterministic(wideNpk, pub, ephemeral); !errors.Is(err, ErrBadKeyLength) {
		t.Errorf("encap to a %d byte recipient key under Npk 48 returned %d/%d bytes and error %v, want ErrBadKeyLength",
			len(pub), len(gotSecret), len(gotEnc), err)
	}

	// both scalar gates read Nsk — encap's ephemeral scalar and decap's private key
	wideNsk := hpkeFieldProbeParams(32)
	wideNsk.Nsk = 48
	if gotSecret, gotEnc, err := hpkeEncapDeterministic(wideNsk, pub, ephemeral); !errors.Is(err, ErrBadKeyLength) {
		t.Errorf("encap from a %d byte ephemeral scalar under Nsk 48 returned %d/%d bytes and error %v, want ErrBadKeyLength",
			len(ephemeral), len(gotSecret), len(gotEnc), err)
	}
	if gotSecret, err := hpkeDecap(wideNsk, priv, kemOutput); !errors.Is(err, ErrBadKeyLength) {
		t.Errorf("decap with a %d byte private key under Nsk 48 returned %d bytes and error %v, want ErrBadKeyLength",
			len(priv), len(gotSecret), err)
	}

	// decap gates the kem output on Nenc, not on the Npk that holds the same 32
	wideNenc := hpkeFieldProbeParams(32)
	wideNenc.Nenc = 48
	if gotSecret, err := hpkeDecap(wideNenc, priv, kemOutput); !errors.Is(err, ErrBadKemOutput) {
		t.Errorf("decap of a %d byte kem output under Nenc 48 returned %d bytes and error %v, want ErrBadKemOutput",
			len(kemOutput), len(gotSecret), err)
	}
}

// The probe suite the test above builds on: a SuiteParams no registry holds, in which
// every length field carries the same background value. The caller then widens the single
// field it means to separate, so the field under test is the only one the probe can be
// answered by and every other length says the opposite.
//
// Nothing is passed per field. A helper taking the lengths one by one — positionally or by
// name — can be called with one left out, and a length left out is zero: a gate comparing
// against zero refuses every input, which is exactly what these probes expect to see and
// would make one pass while asserting nothing. Setting all of them from one argument is
// what makes that unrepresentable, and it is why NsigPub and NsigPriv are here at all
// despite no kem function naming them — they are 32 in both registered entries too, so a
// gate that read one would be invisible everywhere else in this file.
func hpkeFieldProbeParams(background int) *SuiteParams {
	return &SuiteParams{
		Suite:    CipherSuiteX25519ChaCha20Sha256Ed25519,
		KemId:    HpkeKemX25519HkdfSha256,
		KdfId:    HpkeKdfHkdfSha256,
		AeadId:   HpkeAeadChaCha20Poly1305,
		Nh:       background,
		Nk:       background,
		Nn:       background,
		Nt:       background,
		Nsecret:  background,
		Nenc:     background,
		Npk:      background,
		Nsk:      background,
		NsigPub:  background,
		NsigPriv: background,
	}
}

// TestHpkeRefusesALowOrderPeerKey carries guardrail 3's refusal through the kem. X25519DH
// reports a low order point as ErrInvalidPoint and crypto_x25519_test.go pins that; what is
// unproven until here is that the kem propagates it rather than deriving a shared secret
// from an all zero diffie-hellman output, which is what the whole guardrail exists to stop
// and which would look exactly like a working key exchange to both parties.
//
// Both directions are covered because the two functions reach the curve through different
// arguments: encap takes the peer key as a recipient public key, decap takes it as a kem
// output off the wire. Nothing else in the package covers either: with the kem swallowing
// X25519DH's error and deriving from an all zero output, in encap, in decap, or in both,
// this is the only test in mls that fails.
//
// The count is what keeps the loop honest, and it counts the same quantity
// crypto_x25519_test.go counts: points that reached the exchange, not points that were
// refused. Those are different, and only the first is a measure of coverage. crypto/ecdh
// accepts every 32 byte u coordinate today and refuses at the exchange, so all four points
// reach X25519DH; a parser that started refusing them at parse would satisfy every
// assertion in the body — ErrInvalidPoint is ErrInvalidPoint whichever gate returned it —
// and a counter of refusals would go on reporting four while the exchange refusal this
// test exists for went unexercised. Counting refusals here was measurably wrong, not
// theoretically: with a parse blacklist and the swallow applied together, the refusal
// counter left this test green while the kem derived keys from a zero shared secret.
func TestHpkeRefusesALowOrderPeerKey(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	priv, _, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x08}, 32))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	ephemeral := HpkePrivateKey(bytes.Repeat([]byte{0x09}, params.Nsk))
	reachedTheExchange := 0
	for i, point := range x25519LowOrderPoints {
		// the gate both entry points below parse this peer key through. Refusing here is
		// also not a zero secret and is acceptable, but it says nothing about the kem, so
		// the point is not counted and its assertions are not run.
		if _, err := X25519PublicKey(point); err != nil {
			if !errors.Is(err, ErrInvalidPoint) {
				t.Errorf("point %d: parse error = %v, want ErrInvalidPoint", i, err)
			}
			continue
		}
		reachedTheExchange++
		secret, enc, err := hpkeEncapDeterministic(params, HpkePublicKey(point), ephemeral)
		if !errors.Is(err, ErrInvalidPoint) {
			t.Errorf("point %d: encap error = %v, want ErrInvalidPoint", i, err)
			continue
		}
		if secret != nil || enc != nil {
			t.Errorf("point %d: encap refused and returned %d/%d bytes anyway", i, len(secret), len(enc))
			continue
		}
		secret, err = hpkeDecap(params, priv, point)
		if !errors.Is(err, ErrInvalidPoint) {
			t.Errorf("point %d: decap error = %v, want ErrInvalidPoint", i, err)
			continue
		}
		if secret != nil {
			t.Errorf("point %d: decap refused and returned %d bytes anyway", i, len(secret))
		}
	}
	if reachedTheExchange == 0 {
		t.Errorf("none of the %d low order points reached the exchange, so this test covered nothing", len(x25519LowOrderPoints))
	}
}

// TestHpkeEncapFailsWhenRandomFails is the key draw's own failure path. An encapsulation
// that answered a dead entropy source with an ephemeral key from somewhere else is worse
// than one that fails, because the peer would decapsulate it happily. The error has to be
// the reader's own rather than one of this package's sentinels, for the same reason
// X25519GenerateKey's is.
func TestHpkeEncapFailsWhenRandomFails(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	pub := mustDeriveHpkePublicKey(t, params, 0x0a)
	entropyIsDown := errors.New("entropy source is down")
	secret, enc, err := hpkeEncap(failingReader{err: entropyIsDown}, params, pub)
	if !errors.Is(err, entropyIsDown) {
		t.Errorf("error = %v, want the reader's own error", err)
	}
	if secret != nil || enc != nil {
		t.Errorf("a failing reader still produced %d/%d bytes", len(secret), len(enc))
	}
	secret, enc, err = hpkeEncap(&shortReader{remaining: params.Nsk - 1}, params, pub)
	if err == nil {
		t.Errorf("a short reader still produced an encapsulation")
	}
	if secret != nil || enc != nil {
		t.Errorf("a short reader still produced %d/%d bytes", len(secret), len(enc))
	}
}

// One key pair's public half from a constant ikm, so a test that needs a well formed
// recipient key and nothing else does not spell out the derivation and its error handling
// each time. It is deliberately not a vector key: the tests using it are about lengths,
// entropy and refusals, and reaching for a published key there would suggest the value
// mattered.
func mustDeriveHpkePublicKey(t *testing.T, params *SuiteParams, ikmByte byte) HpkePublicKey {
	t.Helper()
	_, pub, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{ikmByte}, params.Nsk))
	if err != nil {
		t.Fatalf("HpkeDeriveKeyPair: %v", err)
	}
	return pub
}

func TestHpkeContextSequenceAdvances(t *testing.T) {
	// each Seal must use base_nonce XOR seq. a context that reused nonce zero would
	// still decrypt correctly under a matching receiver, so the only way to catch it
	// is to assert the ciphertexts differ for identical plaintext.
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	sender, err := hpkeKeySchedule(params, bytes.Repeat([]byte{0x05}, 32), []byte("info"))
	if err != nil {
		t.Fatalf("key schedule: %v", err)
	}
	receiver, err := hpkeKeySchedule(params, bytes.Repeat([]byte{0x05}, 32), []byte("info"))
	if err != nil {
		t.Fatalf("key schedule: %v", err)
	}
	plaintext := []byte("the same plaintext every time")
	var previous []byte
	for i := 0; i < 4; i++ {
		ciphertext, err := sender.Seal([]byte("aad"), plaintext)
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		if bytes.Equal(ciphertext, previous) {
			t.Fatalf("seal %d repeated the previous ciphertext: the sequence did not advance", i)
		}
		previous = ciphertext
		back, err := receiver.Open([]byte("aad"), ciphertext)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if !bytes.Equal(back, plaintext) {
			t.Fatalf("open %d returned %q", i, back)
		}
	}
}

func TestHpkeContextOpenRejectsTamper(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	sender, err := hpkeKeySchedule(params, bytes.Repeat([]byte{0x06}, 32), nil)
	if err != nil {
		t.Fatalf("key schedule: %v", err)
	}
	ciphertext, err := sender.Seal([]byte("aad"), []byte("plaintext"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for i := range ciphertext {
		receiver, err := hpkeKeySchedule(params, bytes.Repeat([]byte{0x06}, 32), nil)
		if err != nil {
			t.Fatalf("key schedule: %v", err)
		}
		tampered := bytes.Clone(ciphertext)
		tampered[i] ^= 0x01
		if _, err := receiver.Open([]byte("aad"), tampered); !errors.Is(err, ErrAeadOpen) {
			t.Fatalf("flipping byte %d: error = %v, want ErrAeadOpen", i, err)
		}
	}
	receiver, err := hpkeKeySchedule(params, bytes.Repeat([]byte{0x06}, 32), nil)
	if err != nil {
		t.Fatalf("key schedule: %v", err)
	}
	if _, err := receiver.Open([]byte("different aad"), ciphertext); !errors.Is(err, ErrAeadOpen) {
		t.Fatalf("wrong aad: error = %v, want ErrAeadOpen", err)
	}
}

func TestHpkeContextExportIsLabelSeparated(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	ctx, err := hpkeKeySchedule(params, bytes.Repeat([]byte{0x07}, 32), nil)
	if err != nil {
		t.Fatalf("key schedule: %v", err)
	}
	a, err := ctx.Export([]byte("context a"), 32)
	if err != nil {
		t.Fatalf("export a: %v", err)
	}
	b, err := ctx.Export([]byte("context b"), 32)
	if err != nil {
		t.Fatalf("export b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("different exporter contexts produced the same value")
	}
	// export must not consume a sequence number
	again, err := ctx.Export([]byte("context a"), 32)
	if err != nil {
		t.Fatalf("export a again: %v", err)
	}
	if !bytes.Equal(a, again) {
		t.Fatalf("export is not stable across calls")
	}
}

func TestHpkeAeadKeyLengthIsSuiteBound(t *testing.T) {
	// 0x0003 is a 32-byte key, 0x0001 is 16. a provider that hardcoded 32 would pass
	// every chacha test and silently fail on the aes suite.
	for _, testCase := range []struct {
		suite CipherSuite
		nk    int
	}{
		{suite: CipherSuiteX25519AesGcm128Sha256Ed25519, nk: 16},
		{suite: CipherSuiteX25519ChaCha20Sha256Ed25519, nk: 32},
	} {
		params, err := LookupSuite(testCase.suite)
		if err != nil {
			t.Fatalf("LookupSuite: %v", err)
		}
		if _, err := hpkeNewAead(params, make([]byte, testCase.nk)); err != nil {
			t.Errorf("suite %#04x rejected a %d-byte key: %v", uint16(testCase.suite), testCase.nk, err)
		}
		if _, err := hpkeNewAead(params, make([]byte, testCase.nk+1)); !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("suite %#04x accepted a %d-byte key", uint16(testCase.suite), testCase.nk+1)
		}
	}
}
