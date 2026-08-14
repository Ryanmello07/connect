// RFC 9180 HPKE, base mode only, DHKEM(X25519, HKDF-SHA256) with HKDF-SHA256 and
// either ChaCha20-Poly1305 or AES-128-GCM.
//
// MLS uses only single-shot base-mode seal and open, but this file implements the
// full context with its sequence number because the RFC's own test vectors exercise
// the sequence path and a one-shot helper cannot be tested against them.
//
// psk, auth and auth-psk modes are deliberately absent: the v1 profile has no PSKs
// and no external senders, so there is no caller for them and no untested code.
//
// Two of the identifiers this file concatenates collide. RFC 9180 section 7.2 gives
// HKDF-SHA256 the kdf code point 0x0001 and section 7.3 gives AES-128-GCM the aead
// code point 0x0001, in two separate registries, so the two compare equal. suite.go
// declares HpkeKdfId and HpkeAeadId as distinct types, which makes a registry entry
// writing one where the other belongs a compile error — but that does not reach the
// three appends below. binary.BigEndian.AppendUint16 takes a uint16, and the explicit
// conversion it demands is exactly where the typing is discarded, so writing
// uint16(params.AeadId) into the kdf position here still compiles. That is why the
// suite id is pinned by vectors from both registered suites rather than by an equality
// check on a single one: the two agree on the kdf and disagree on the aead, so a
// transposition that is invisible on 0x0001 moves every derived byte on 0x0003.
package mls

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"io"
)

const (
	hpkeVersionLabel = "HPKE-v1"
	hpkeModeBase     = byte(0x00)
)

// The kdf output size both registered suites fix, and the longest output HKDF-Expand
// can produce from it. RFC 5869 section 2.3 stops the expansion counter at 255, so
// 255*Nh is a hard ceiling rather than a policy: past it there is no key to return.
// This is written against the one kdf the package instantiates rather than read from
// SuiteParams, because the ceiling belongs to HMAC-SHA256 and not to a ciphersuite,
// and a test asserts the registry has not drifted away from it.
const (
	hpkeKdfNh           = sha256.Size
	hpkeMaxExpandLength = 255 * hpkeKdfNh
)

// The kem half of the suite identifier, RFC 9180 section 5.1. Read the kem code point
// and nothing else: the kdf and aead ids are not part of a kem derivation, and a kem
// context that carried them would still produce 32 usable-looking bytes.
func hpkeKemSuiteId(params *SuiteParams) []byte {
	suiteId := make([]byte, 0, 5)
	suiteId = append(suiteId, "KEM"...)
	return binary.BigEndian.AppendUint16(suiteId, uint16(params.KemId))
}

// The whole suite identifier, RFC 9180 section 5.1, in the order the RFC fixes: kem,
// then kdf, then aead. The order is the part worth guarding — see the file comment on
// the 0x0001 collision — and the "HPKE" prefix is what keeps a suite id from being
// mistaken for the kem one above, which is five bytes shorter and starts differently
// for exactly that reason.
func hpkeSuiteId(params *SuiteParams) []byte {
	suiteId := make([]byte, 0, 10)
	suiteId = append(suiteId, "HPKE"...)
	suiteId = binary.BigEndian.AppendUint16(suiteId, uint16(params.KemId))
	suiteId = binary.BigEndian.AppendUint16(suiteId, uint16(params.KdfId))
	return binary.BigEndian.AppendUint16(suiteId, uint16(params.AeadId))
}

// LabeledExtract, RFC 9180 section 4. hkdf.Extract takes (ikm, salt) — the reverse of
// the HKDF-Extract(salt, ikm) the RFC and every spec text in this project write — so
// the swap lives here and nowhere else (spec A section 5.9, guardrail 1), and
// crypto_forbidden_test.go holds it to two files.
//
// The only error hkdf.Extract returns is from the fips140-only mode check, which
// refuses a non approved hash or a short secret. sha256 is approved and the secret
// always carries the seven byte version label, the suite id and a non empty label
// ahead of the caller's material, so under this file's own call sites it cannot fire.
// It is therefore a panic rather than a silently ignored error: a caller handed a nil
// prk would derive keys from nothing and report success.
func hpkeLabeledExtract(suiteId []byte, salt []byte, label string, ikm []byte) []byte {
	labeledIkm := make([]byte, 0, len(hpkeVersionLabel)+len(suiteId)+len(label)+len(ikm))
	labeledIkm = append(labeledIkm, hpkeVersionLabel...)
	labeledIkm = append(labeledIkm, suiteId...)
	labeledIkm = append(labeledIkm, label...)
	labeledIkm = append(labeledIkm, ikm...)
	prk, err := hkdf.Extract(sha256.New, labeledIkm, salt)
	if err != nil {
		panic("mls: hkdf extract failed with a compiled-in sha256: " + err.Error())
	}
	return prk
}

// LabeledExpand, RFC 9180 section 4. The info argument of crypto/hkdf.Expand is typed
// string but is not text; the conversion is byte preserving.
//
// The length is refused here rather than left to hkdf.Expand, because hkdf.Expand does
// not refuse a negative one — it dies on it. crypto/internal/fips140/hkdf opens Expand
// with out := make([]byte, 0, keyLen), reached before the expansion loop and before the
// counter overflow check that loop carries, so a negative keyLen is a makeslice panic
// and the process goes with it. Measured on go1.26.5: -1 panics with "makeslice: cap out
// of range", 8160 returns 8160 bytes, 8161 returns "hkdf: requested key length too
// large". So this guard converts a caller supplied length into a typed error instead of
// a process kill, which is what task 8's Export(exporterContext, length) needs — that
// length comes from a caller, not from the suite.
//
// The upper bound is one bound and not two. 255*Nh is 8160 and the two byte I2OSP prefix
// only misencodes above 65535, so the ceiling refuses every length the prefix could wrap
// long before the prefix could wrap: the uint16 conversion below is lossless because the
// ceiling made it so, and a separate length > 65535 branch here would be unreachable.
// The ceiling is not this package's own policy either — hkdf.Expand enforces the same
// 255*Nh limit, which is the fact hpke_test.go pins the constant against rather than
// pinning it against itself.
func hpkeLabeledExpand(suiteId []byte, prk []byte, label string, info []byte, length int) ([]byte, error) {
	if length < 0 || length > hpkeMaxExpandLength {
		return nil, ErrBadKeyLength
	}
	labeledInfo := make([]byte, 0, 2+len(hpkeVersionLabel)+len(suiteId)+len(label)+len(info))
	labeledInfo = binary.BigEndian.AppendUint16(labeledInfo, uint16(length))
	labeledInfo = append(labeledInfo, hpkeVersionLabel...)
	labeledInfo = append(labeledInfo, suiteId...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	return hkdf.Expand(sha256.New, prk, string(labeledInfo), length)
}

// A serialized hpke public key, in the SerializePublicKey encoding RFC 9180 section 7.1.1
// fixes for DHKEM(X25519): the raw 32 byte u coordinate, no prefix. Named byte slices
// rather than an interface, because MLS carries them as opaque vectors and every consumer
// needs the bytes anyway — and named at all rather than left as []byte so a signature
// cannot silently take a private key where a public one belongs.
type HpkePublicKey []byte

// A serialized hpke private key, the 32 byte x25519 scalar as DeriveKeyPair expanded it.
// It is deliberately not the clamped form: crypto/ecdh clamps inside the multiplication
// and RFC 9180 serializes the unclamped scalar, so storing the clamped one here would
// disagree with every published vector.
type HpkePrivateKey []byte

// DeriveKeyPair, RFC 9180 section 7.1.3. For DHKEM(X25519) the expanded scalar is used
// directly: there is no rejection sampling — that is the NIST curves' branch of the same
// section — and no clamping, which is x25519's own and happens inside the multiplication.
//
// The kem suite id is the one that belongs here rather than the whole suite id. A key pair
// is a property of the kem alone, so deriving it under the full identifier would give the
// same ikm a different key pair per aead, and the two registered suites would stop sharing
// a keystore for no reason RFC 9180 states.
func HpkeDeriveKeyPair(params *SuiteParams, ikm []byte) (HpkePrivateKey, HpkePublicKey, error) {
	suiteId := hpkeKemSuiteId(params)
	dkpPrk := hpkeLabeledExtract(suiteId, nil, "dkp_prk", ikm)
	scalar, err := hpkeLabeledExpand(suiteId, dkpPrk, "sk", nil, params.Nsk)
	if err != nil {
		return nil, nil, err
	}
	priv, err := X25519PrivateKey(scalar)
	if err != nil {
		return nil, nil, err
	}
	return HpkePrivateKey(priv.Bytes()), HpkePublicKey(priv.PublicKey().Bytes()), nil
}

// ExtractAndExpand, RFC 9180 section 4.1: the hash that turns a raw diffie-hellman output
// into a kem shared secret. Skipping it and returning dh would produce 32 bytes that
// round-trip perfectly between an encap and a decap that both skipped it, which is why the
// vector table rather than the round trip is what holds this function in place.
func hpkeExtractAndExpand(params *SuiteParams, dh []byte, kemContext []byte) ([]byte, error) {
	suiteId := hpkeKemSuiteId(params)
	eaePrk := hpkeLabeledExtract(suiteId, nil, "eae_prk", dh)
	return hpkeLabeledExpand(suiteId, eaePrk, "shared_secret", kemContext, params.Nsecret)
}

// Encap, RFC 9180 section 4.1, drawing the ephemeral key from the reader it is handed.
// The reader is a parameter rather than a package level source so a caller can reproduce a
// published encapsulation; it reaches x25519 through X25519GenerateKey, which reads it
// itself because ecdh.GenerateKey no longer does.
func hpkeEncap(random io.Reader, params *SuiteParams, pub HpkePublicKey) ([]byte, []byte, error) {
	ephemeral, err := X25519GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	return hpkeEncapDeterministic(params, pub, HpkePrivateKey(ephemeral.Bytes()))
}

// Encap with the ephemeral key supplied, so the RFC's vectors drive production code rather
// than a parallel implementation written for the test. It is the whole of Encap; the
// randomized entry point above is only the key draw in front of it.
//
// kem_context is enc || pkRm and the order is load bearing. Both halves are 32 bytes of
// public key, so a transposition changes no length, returns no error and still agrees with
// a decap transposed the same way — it is visible only against a published shared secret.
// The same is true of which key goes where: pkRm is the recipient's static key and enc is
// this call's ephemeral public key, and writing enc twice, which is what reading the
// ephemeral key for both positions would do, is equally silent.
func hpkeEncapDeterministic(params *SuiteParams, pub HpkePublicKey, ephemeralPriv HpkePrivateKey) ([]byte, []byte, error) {
	if len(ephemeralPriv) != params.Nsk {
		return nil, nil, ErrBadKeyLength
	}
	if len(pub) != params.Npk {
		return nil, nil, ErrBadKeyLength
	}
	ephemeral, err := X25519PrivateKey(ephemeralPriv)
	if err != nil {
		return nil, nil, err
	}
	recipient, err := X25519PublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	dh, err := X25519DH(ephemeral, recipient)
	if err != nil {
		return nil, nil, err
	}
	kemOutput := ephemeral.PublicKey().Bytes()
	kemContext := make([]byte, 0, len(kemOutput)+len(pub))
	kemContext = append(kemContext, kemOutput...)
	kemContext = append(kemContext, pub...)
	sharedSecret, err := hpkeExtractAndExpand(params, dh, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return sharedSecret, kemOutput, nil
}

// Decap, RFC 9180 section 4.1. The recipient's half of the kem context is recomputed from
// its own private key rather than taken from a caller, which is the only way the two sides
// can be made to agree on pkRm without a second wire field to get wrong — and it is why a
// decap that put its own key first would still round trip against nothing but itself.
//
// A wrong length is refused before the curve rather than at it, and the two lengths get
// different sentinels on purpose: a kem output is a peer's bytes off the wire, while a
// private key of the wrong length is this process's own bug, and a caller triaging the two
// needs to tell them apart.
func hpkeDecap(params *SuiteParams, priv HpkePrivateKey, kemOutput []byte) ([]byte, error) {
	if len(kemOutput) != params.Nenc {
		return nil, ErrBadKemOutput
	}
	if len(priv) != params.Nsk {
		return nil, ErrBadKeyLength
	}
	recipient, err := X25519PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	ephemeral, err := X25519PublicKey(kemOutput)
	if err != nil {
		return nil, err
	}
	dh, err := X25519DH(recipient, ephemeral)
	if err != nil {
		return nil, err
	}
	recipientPub := recipient.PublicKey().Bytes()
	kemContext := make([]byte, 0, len(kemOutput)+len(recipientPub))
	kemContext = append(kemContext, kemOutput...)
	kemContext = append(kemContext, recipientPub...)
	return hpkeExtractAndExpand(params, dh, kemContext)
}
