// What the one x25519 call site must do, and the part of it a smoke test cannot see.
// Agreement alone is nearly free: a function returning a constant, or returning its own
// argument, makes both parties agree on 32 bytes and passes a round trip unchallenged.
// So the round trip is joined here by two things it cannot state — that the secret is
// the one RFC 7748 publishes for a known pair of keys, and that it moves when the peer
// key moves — and by the refusals, which are the reason this wrapper exists at all.
//
// The low order case is the whole point of guardrail 3. crypto/ecdh accepts any 32 byte
// u coordinate and refuses at the exchange, so the test that names that refusal counts
// how many points actually reached it: a parser that rejected everything would otherwise
// skip the loop body and report success.
//
// There is no hex helper declared here. This package has exactly one and it is the
// interop harness's MustHex, which has not landed yet, so the vectors below decode
// inline rather than growing a second one that would collide with it.
package mls

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

// The RFC 7748 section 6.1 key pairs. Both are also carried by the standard library's
// own crypto/ecdh vector table, which is where the values here were checked against
// something other than this package.
const (
	rfc7748AlicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	rfc7748AlicePublic  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	rfc7748BobPrivate   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	rfc7748BobPublic    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	rfc7748SharedSecret = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
)

// One published exchange: a scalar, a peer u coordinate and the answer. The section 5.2
// row is not a two party exchange at all but a bare scalar multiplication, which is why
// its peer key is not any party's public key — it is there so the table holds a u
// coordinate that was never produced by this package's own key generation.
var x25519ExchangeVectors = []struct {
	name          string
	privateKey    string
	peerPublicKey string
	sharedSecret  string
}{
	{
		name:          "rfc 7748 section 6.1, alice to bob",
		privateKey:    rfc7748AlicePrivate,
		peerPublicKey: rfc7748BobPublic,
		sharedSecret:  rfc7748SharedSecret,
	},
	{
		name:          "rfc 7748 section 6.1, bob to alice",
		privateKey:    rfc7748BobPrivate,
		peerPublicKey: rfc7748AlicePublic,
		sharedSecret:  rfc7748SharedSecret,
	},
	{
		name:          "rfc 7748 section 5.2, first vector",
		privateKey:    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
		peerPublicKey: "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
		sharedSecret:  "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
	},
}

// The public key each published scalar derives to. Separate from the exchange table
// because the scalar of the section 5.2 vector has no published public key, and a row
// carrying an empty expectation would be a row asserting nothing.
var x25519DerivationVectors = []struct {
	name       string
	privateKey string
	publicKey  string
}{
	{name: "rfc 7748 section 6.1, alice", privateKey: rfc7748AlicePrivate, publicKey: rfc7748AlicePublic},
	{name: "rfc 7748 section 6.1, bob", privateKey: rfc7748BobPrivate, publicKey: rfc7748BobPublic},
}

// TestX25519RoundTrip is the plan's agreement check: two freshly generated parties reach
// the same 32 bytes from opposite sides. On its own it is satisfied by any symmetric
// function, which is what the known answer and sensitivity tests below are for.
func TestX25519RoundTrip(t *testing.T) {
	a, err := X25519GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate a: %v", err)
	}
	b, err := X25519GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate b: %v", err)
	}
	ab, err := X25519DH(a, b.PublicKey())
	if err != nil {
		t.Fatalf("dh ab: %v", err)
	}
	ba, err := X25519DH(b, a.PublicKey())
	if err != nil {
		t.Fatalf("dh ba: %v", err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatalf("shared secrets differ: %x vs %x", ab, ba)
	}
	if len(ab) != 32 {
		t.Fatalf("shared secret is %d bytes, want 32", len(ab))
	}
}

// TestX25519KnownAnswer pins the output bytes themselves against RFC 7748, which is the
// only assertion here that a constant returning implementation cannot satisfy. It is
// also the only exercise of the two parsers on their accepting path, so a parser that
// refused everything fails here rather than quietly emptying the tests below.
func TestX25519KnownAnswer(t *testing.T) {
	for _, vector := range x25519ExchangeVectors {
		privateBytes, err := hex.DecodeString(vector.privateKey)
		if err != nil {
			t.Fatalf("%s: private key hex: %v", vector.name, err)
		}
		peerBytes, err := hex.DecodeString(vector.peerPublicKey)
		if err != nil {
			t.Fatalf("%s: peer public key hex: %v", vector.name, err)
		}
		want, err := hex.DecodeString(vector.sharedSecret)
		if err != nil {
			t.Fatalf("%s: shared secret hex: %v", vector.name, err)
		}
		priv, err := X25519PrivateKey(privateBytes)
		if err != nil {
			t.Errorf("%s: X25519PrivateKey: %v", vector.name, err)
			continue
		}
		pub, err := X25519PublicKey(peerBytes)
		if err != nil {
			t.Errorf("%s: X25519PublicKey: %v", vector.name, err)
			continue
		}
		secret, err := X25519DH(priv, pub)
		if err != nil {
			t.Errorf("%s: X25519DH: %v", vector.name, err)
			continue
		}
		if !bytes.Equal(secret, want) {
			t.Errorf("%s: shared secret = %x, want %x", vector.name, secret, want)
		}
	}
}

// TestX25519PrivateKeyDerivesThePublishedPublicKey states that a parsed scalar carries
// the key pair RFC 7748 says it does. Without it a parser could return some other
// party's key and every exchange in the table above would still agree, since both sides
// of a vector are checked against the published secret rather than against each other.
func TestX25519PrivateKeyDerivesThePublishedPublicKey(t *testing.T) {
	for _, vector := range x25519DerivationVectors {
		privateBytes, err := hex.DecodeString(vector.privateKey)
		if err != nil {
			t.Fatalf("%s: private key hex: %v", vector.name, err)
		}
		want, err := hex.DecodeString(vector.publicKey)
		if err != nil {
			t.Fatalf("%s: public key hex: %v", vector.name, err)
		}
		priv, err := X25519PrivateKey(privateBytes)
		if err != nil {
			t.Errorf("%s: X25519PrivateKey: %v", vector.name, err)
			continue
		}
		if got := priv.PublicKey().Bytes(); !bytes.Equal(got, want) {
			t.Errorf("%s: public key = %x, want %x", vector.name, got, want)
		}
	}
}

// TestX25519SecretDependsOnThePeerKey is the property a round trip cannot reach: hold
// one side fixed, change the other, and the secret must change. A helper that ignored
// its arguments and returned a constant agrees with itself perfectly and fails only
// here and at the known answer table.
func TestX25519SecretDependsOnThePeerKey(t *testing.T) {
	local, err := X25519GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate local: %v", err)
	}
	first, err := X25519GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate first peer: %v", err)
	}
	second, err := X25519GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate second peer: %v", err)
	}
	withFirst, err := X25519DH(local, first.PublicKey())
	if err != nil {
		t.Fatalf("dh with first peer: %v", err)
	}
	withSecond, err := X25519DH(local, second.PublicKey())
	if err != nil {
		t.Fatalf("dh with second peer: %v", err)
	}
	if bytes.Equal(withFirst, withSecond) {
		t.Fatalf("two different peer keys produced the same secret: %x", withFirst)
	}
	// and the same pair twice must not move, or the difference above says nothing
	again, err := X25519DH(local, first.PublicKey())
	if err != nil {
		t.Fatalf("dh with first peer again: %v", err)
	}
	if !bytes.Equal(withFirst, again) {
		t.Fatalf("the same pair produced %x then %x", withFirst, again)
	}
}

// TestX25519LowOrderPointIsAnError is the refusal guardrail 3 exists for. Master
// section 7.2 and spec A section 5.4: the banned sdk.GenerateSharedSecret returns an
// all zero secret for these points, and a caller that logged it and continued would
// encrypt under a key its peer chose.
//
// The count at the end is what keeps the loop honest. crypto/ecdh accepts every 32 byte
// u coordinate today and refuses at the exchange, so all four points reach X25519DH; a
// parser that started refusing them would skip every assertion in the body and leave
// this test passing while covering nothing.
func TestX25519LowOrderPointIsAnError(t *testing.T) {
	lowOrderPoints := [][]byte{
		// the small subgroup points of curve25519: the identity, the order one
		// point, and the two of order eight. Clamping makes every scalar a
		// multiple of eight, so all four drive the x25519 output to zero.
		make([]byte, 32),
		{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
			0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
		{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
			0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
	}
	priv, err := X25519GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	reachedTheExchange := 0
	for i, point := range lowOrderPoints {
		pub, err := X25519PublicKey(point)
		if err != nil {
			// rejecting at parse is also acceptable, and is still not a zero
			// secret, but it has to be the point refusal: these are all 32 bytes
			// long, so a length error here would mean the gate misread them.
			if !errors.Is(err, ErrInvalidPoint) {
				t.Errorf("point %d: parse error = %v, want ErrInvalidPoint", i, err)
			}
			continue
		}
		reachedTheExchange++
		secret, err := X25519DH(priv, pub)
		if !errors.Is(err, ErrInvalidPoint) {
			t.Errorf("point %d: error = %v, want ErrInvalidPoint", i, err)
		}
		if secret != nil {
			t.Errorf("point %d: returned a secret alongside the error: %x", i, secret)
		}
	}
	if reachedTheExchange == 0 {
		t.Errorf("all %d low order points were refused at parse, so the exchange refusal this test is named for went unexercised", len(lowOrderPoints))
	}
}

// TestX25519RejectsWrongKeyLengths covers the lengths that are not 32. The refusal must
// come with nothing in hand: a key returned beside the error is a key some caller that
// checks the wrong half of the pair first will use. The accepting case is asserted in
// the same place because without it a parser hardwired to refuse everything passes this
// test and empties the low order one.
func TestX25519RejectsWrongKeyLengths(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		priv, err := X25519PrivateKey(make([]byte, n))
		if !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("X25519PrivateKey(%d bytes) error = %v, want ErrBadKeyLength", n, err)
		}
		if priv != nil {
			t.Errorf("X25519PrivateKey(%d bytes) refused and returned a key anyway", n)
		}
		pub, err := X25519PublicKey(make([]byte, n))
		if !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("X25519PublicKey(%d bytes) error = %v, want ErrBadKeyLength", n, err)
		}
		if pub != nil {
			t.Errorf("X25519PublicKey(%d bytes) refused and returned a key anyway", n)
		}
	}
	accepted := make([]byte, x25519KeySize)
	for i := range accepted {
		accepted[i] = byte(i + 1)
	}
	if _, err := X25519PrivateKey(accepted); err != nil {
		t.Errorf("X25519PrivateKey refused a %d byte scalar: %v", x25519KeySize, err)
	}
	if _, err := X25519PublicKey(accepted); err != nil {
		t.Errorf("X25519PublicKey refused a %d byte u coordinate: %v", x25519KeySize, err)
	}
}

// TestX25519KeySizeAgreesWithTheRegistry ties the literal this file introduces to the
// registry that has to agree with it. Only the suites naming the x25519 kem are checked,
// since a suite on a different curve would rightly carry different lengths and is not
// this helper's business.
func TestX25519KeySizeAgreesWithTheRegistry(t *testing.T) {
	checked := 0
	for _, suite := range Suites() {
		params, err := LookupSuite(suite)
		if err != nil {
			t.Errorf("LookupSuite(%#04x): %v", uint16(suite), err)
			continue
		}
		if params.KemId != HpkeKemX25519HkdfSha256 {
			continue
		}
		checked++
		if params.Npk != x25519KeySize {
			t.Errorf("%s: Npk = %d, x25519 public keys are %d bytes", params.Name, params.Npk, x25519KeySize)
		}
		if params.Nsk != x25519KeySize {
			t.Errorf("%s: Nsk = %d, x25519 scalars are %d bytes", params.Name, params.Nsk, x25519KeySize)
		}
		if params.Nsecret != x25519KeySize {
			t.Errorf("%s: Nsecret = %d, x25519 shared secrets are %d bytes", params.Name, params.Nsecret, x25519KeySize)
		}
	}
	if checked == 0 {
		t.Errorf("no registered suite names kem %#04x, so this test compared nothing", HpkeKemX25519HkdfSha256)
	}
}
