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
// code point 0x0001, in two separate registries, so writing one where the other
// belongs compiles and compares equal. Nothing in the type system separates them —
// both are uint16 — which is why the suite id built here is pinned by vectors from
// both registered suites rather than by an equality check on a single one: the two
// agree on the kdf and disagree on the aead, so a transposition that is invisible on
// 0x0001 moves every derived byte on 0x0003.
package mls

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
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
	return binary.BigEndian.AppendUint16(suiteId, params.KemId)
}

// The whole suite identifier, RFC 9180 section 5.1, in the order the RFC fixes: kem,
// then kdf, then aead. The order is the part worth guarding — see the file comment on
// the 0x0001 collision — and the "HPKE" prefix is what keeps a suite id from being
// mistaken for the kem one above, which is five bytes shorter and starts differently
// for exactly that reason.
func hpkeSuiteId(params *SuiteParams) []byte {
	suiteId := make([]byte, 0, 10)
	suiteId = append(suiteId, "HPKE"...)
	suiteId = binary.BigEndian.AppendUint16(suiteId, params.KemId)
	suiteId = binary.BigEndian.AppendUint16(suiteId, params.KdfId)
	return binary.BigEndian.AppendUint16(suiteId, params.AeadId)
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
// The length is refused before it is encoded rather than left to hkdf.Expand. Two
// things go wrong otherwise. The two byte prefix is I2OSP(L, 2), so a length above
// 65535 would be encoded modulo 2^16 — a preimage claiming a length the call is not
// making. And crypto/hkdf.Expand answers a negative length with an empty slice and a
// nil error, which is the silently short key this refusal exists to rule out. Past
// this guard the conversion below is lossless by construction.
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
