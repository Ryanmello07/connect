// Typed errors for the storage layer. Every one of them is fatal by construction: spec
// A section 5.9 guardrail 7 says there is no path in this package that reports one and
// carries on, and that rule is what the shape of this file enforces.
//
// The rule has a second half worth stating here, because this is the file a reader
// checks it against. Nothing in this package signals a failure with a bool. The
// verifiers of spec A section 5.7 — VerifyWriteAuth, VerifyRequestAuth and
// VerifyRecoveryProof — return a bare bool because it is the answer to a constant time
// comparison rather than a report of something having gone wrong, and each of their
// callers is asserted to return on false. A predicate that answers a question about a
// legal value is in the same category and not an exception to anything: ClassIsPrunable
// says what a class is, and there is no failure in it to report. Everything that can
// actually fail hands back one of these values, so a caller that wants to continue past
// a failure has to write the code that ignores an error, in plain sight.
//
// Sentinels rather than error structs, and wrapped with %w at each site that has a
// value worth naming, so errors.Is holds for the caller while the message still carries
// the byte or the bucket that was refused.
//
// Every name here is on spec A section 12.1's published surface, which is the surface the
// allowlist test in the message server repo enumerates, and spec B section 12.1 restates
// it. They were not on it originally — that block listed functions and types and no
// errors — and they were added as amendments A-8 and B-8 rather than kept internal,
// because the guardrail above only means anything if the caller can name what it caught:
// an error a server cannot name is one it can only match on message text. A sentinel
// added here is an addition to that surface and belongs in the same commit as the
// amendment that publishes it.
package message

import "errors"

var (
	// Fires when a retention class byte is outside the nine the wire table admits, and
	// when a RetentionClass tag is outside the four the package defines. Both are the
	// same mistake seen from the two sides of the same byte, and a caller that told
	// them apart would be acting on a distinction the wire does not carry.
	ErrRetentionClassUnknown = errors.New("message: retention class is not one of permanent, durable, media or eph")
	// Fires when an eph bucket is past 5. The ladder has six rungs and 0x16 is not a
	// legal wire byte, so this is a refusal rather than a truncation to the top rung:
	// a record written under a manufactured byte is one that every reader refuses,
	// including the sender's own other devices.
	ErrEphBucketOutOfRange = errors.New("message: eph bucket is outside 0..5")
	// Fires when a class other than eph is asked to carry a non zero eph bucket. The
	// bucket is only meaningful under eph, and the alternative to refusing is dropping
	// it silently — which stores the record as though the caller's belief about the
	// bucket had been right.
	ErrEphBucketOnNonEphClass = errors.New("message: a retention class other than eph carries a non zero eph bucket")
	// Fires when EncodeRecord is handed no record at all. A nil here is a caller bug
	// rather than a bad record, and it is reported rather than dereferenced because the
	// server encodes on the read path, where a panic would take a fetch for an unrelated
	// group down with it.
	ErrRecordNil = errors.New("message: no record to encode")
	// Fires when a record's leading format version byte is not the one this package
	// writes. It is its own sentinel rather than a generic decode failure because every
	// offset in the record is only meaningful under a known version, so this is the one
	// refusal a caller can act on — by asking for a newer client rather than by treating
	// the record as corrupt.
	ErrRecordFormatVersion = errors.New("message: record format version is not one this package reads")
	// Fires when the is_commit byte is neither 0 nor 1. The server acts on this field, so
	// it is authenticated, and a decoder that read it as "any non zero is true" would let
	// two implementations that disagree about the byte both believe they had parsed the
	// record while the mac over it says they had not.
	ErrIsCommitNotBoolean = errors.New("message: the is_commit byte is neither 0 nor 1")
	// Fires when a size bucket is past the top of the ladder. There are six rungs and no
	// seventh, and a record naming one has no body length, no ct_body check the server
	// could apply, and no padding rung its sender could have padded to.
	ErrSizeBucketOutOfRange = errors.New("message: size bucket is outside 0..5")
	// Fires in both directions of the blob rule: a record on the blob rung whose blob id
	// is not exactly 32 bytes, and a record off it that carries one at all. The two are
	// one sentinel because they are one rule — the presence of the blob id is the size
	// bucket restated — and a caller that told them apart would be acting on a
	// distinction the record does not carry.
	ErrBlobIdPresence = errors.New("message: blob id presence disagrees with the size bucket")
	// Fires when a ct_body is neither absent nor exactly the ciphertext length of its size
	// bucket. Absent is legal on the read path, where the body may have been erased by
	// retention or skipped by a heads_only fetch; any other length is a body that was not
	// padded to its rung, which leaks the length the padding exists to hide.
	ErrCtBodyLength = errors.New("message: ct_body length is neither absent nor the size bucket's")
)
