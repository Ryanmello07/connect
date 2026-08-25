// Typed errors for the storage layer. Every one of them is fatal by construction: spec
// A section 5.9 guardrail 7 says there is no path in this package that reports one and
// carries on, and that rule is what the shape of this file enforces.
//
// The rule has a second half worth stating here, because this is the file a reader
// checks it against. Nothing in this package signals a failure with a bool. The only
// three helpers that may return a bare bool are the verifiers of spec A section 5.7 —
// VerifyWriteAuth, VerifyRequestAuth and VerifyRecoveryProof — where the bool is the
// answer to a constant time comparison rather than a report of something having gone
// wrong, and each of their callers is asserted to return on false. Everything else
// hands back one of these values, so a caller that wants to continue past a failure has
// to write the code that ignores an error, in plain sight.
//
// Sentinels rather than error structs, and wrapped with %w at each site that has a
// value worth naming, so errors.Is holds for the caller while the message still carries
// the byte or the bucket that was refused.
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
)
