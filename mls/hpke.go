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
