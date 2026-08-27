// The typed errors raised by the key schedule, the psk secret, the transcript hashes
// and the secret tree. Kept out of errors.go so the validation plan and this one never
// edit a single file during parallel waves, which is a merge conflict rather than a
// design boundary but is a real one.
//
// The three psk errors this plan once declared are absent on purpose: ErrPskNonceLength,
// ErrPskType and ErrDuplicatePsk are ValSem401, ValSem402 and ValSem403, and the
// validation plan's errors.go is the single declaration site for every ValSem sentinel.
// This file must never grow one of them back — package mls is one package, so the second
// declaration is a compile error, and a shape where both compiled would mean an
// errors.Is check somewhere in the commit path quietly stopped matching.
package mls

import (
	"errors"
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

var (
	// ErrSecretLength is returned when a secret handed to the key schedule is not
	// KDF.Nh bytes. A short secret expands into a valid looking epoch that no peer
	// agrees with, which surfaces later as an undecryptable message rather than as
	// the length mistake it is.
	ErrSecretLength = errors.New("mls: secret has the wrong length")

	// ErrExportLength is returned when an exporter length exceeds 255*KDF.Nh, which
	// is the most HKDF-Expand can produce.
	ErrExportLength = errors.New("mls: exporter length out of range")

	// ErrEpochErased is returned when a derivation is asked for over an epoch whose
	// secrets have already been erased. An epoch leaving PastEpochWindow has all nine
	// zeroized in place, and a derivation over KDF.Nh zero bytes is not a weak secret,
	// it is a PUBLIC one: any party can compute it with no knowledge of the group. So
	// this is a refusal rather than an answer, for the reason WelcomeSecret returns nil
	// rather than a zero secret — a caller that wrapped a recovery blob to an aged out
	// epoch's export would be wrapping it to a key the attacker also holds, and nothing
	// would report an error.
	ErrEpochErased = errors.New("mls: the epoch's secrets have been erased")

	// ErrGroupContextTrailingBytes names the condition where a serialized GroupContext
	// carries bytes after its extensions vector. syntax.Unmarshal is what enforces full
	// consumption, so this wraps that package's sentinel and a caller matching either
	// name matches the same failure. MLS signs over serialized forms, so a decoder
	// tolerating trailing bytes would accept two encodings of one object and the
	// signature would cover only one of them.
	ErrGroupContextTrailingBytes = fmt.Errorf(
		"mls: group context has trailing bytes: %w", syntax.ErrTrailingBytes)

	// ErrNilGroupContext is returned when a derivation is handed no GroupContext at
	// all. It is a typed refusal rather than the nil pointer dereference the
	// serialization would otherwise raise: syntax.Marshal receives a non nil interface
	// holding a nil pointer, MarshalMLS dereferences it, and the caller gets a panic
	// out of the syntax package naming neither the argument nor the derivation. Every
	// epoch derivation takes its context off a struct field, so an unset field is the
	// way this arrives.
	ErrNilGroupContext = errors.New("mls: no group context was supplied")

	// ErrTranscriptHashLength is returned when a transcript hash is not KDF.Nh bytes.
	ErrTranscriptHashLength = errors.New("mls: transcript hash has the wrong length")

	// ErrPskCount is returned when a psk list cannot be indexed by the uint16 index
	// and count fields PSKLabel carries.
	ErrPskCount = errors.New("mls: too many psks for a uint16 count")

	// ErrSecretTreeLeafOutOfRange is returned for a leaf index outside the tree the
	// secret tree was built for.
	ErrSecretTreeLeafOutOfRange = errors.New("mls: leaf index outside the secret tree")

	// ErrSecretTreeConsumed is returned when the node secrets covering a leaf have
	// already been deleted. It is the forward secrecy property working, not a fault.
	ErrSecretTreeConsumed = errors.New("mls: secret tree node already consumed")

	// ErrRatchetGenerationConsumed is returned for a generation already used and erased.
	ErrRatchetGenerationConsumed = errors.New("mls: ratchet generation already consumed")

	// ErrRatchetGenerationTooFarAhead is returned when a generation is more than
	// MaxGenerationSkip beyond the ratchet head. Without that bound a forged generation
	// number in a received message is an unbounded KDF loop an attacker chooses the
	// length of.
	ErrRatchetGenerationTooFarAhead = errors.New("mls: ratchet generation too far ahead")

	// ErrRatchetExhausted is returned when a ratchet has produced generation 2^32-1 and
	// has no successor to step to.
	ErrRatchetExhausted = errors.New("mls: ratchet generation space exhausted")
)
