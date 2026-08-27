// The RFC 9420 section 8.4 pre shared key identifier, and the two validation rules that
// are about the value rather than about the proposal carrying it.
//
// The v1 profile refuses PreSharedKey proposals outright (spec A section 3.1), one layer
// above this one, at proposal parse. So it is fair to ask why the codec exists at all.
// It exists because a refusal you cannot parse is a refusal you cannot make correctly:
// ValSem401 and ValSem402 are rules ABOUT a PreSharedKeyId, and a rule cannot be checked
// against a structure the implementation declines to decode. It exists because the
// psk_secret vector family has to pass in both directions, and those vectors are not
// empty. And it exists because the empty psk secret is an input to every epoch this
// product does derive, so a defect in the non empty case is invisible from here and
// surfaces at the first interop test.
//
// Which is the reason it is written as though it ships. Nothing in this file takes the
// shortcut that the list is always empty.
package mls

import (
	"errors"
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// The two refusals this file makes are ValSem401 and ValSem402 in the validation plan's
// catalogue, and that plan owns the single declaration site for ErrPskNonceLength and
// ErrPskType. Neither those names nor ValSem itself has landed in this package yet, so
// the refusals are carried by the two unexported values below until they do.
//
// Unexported is the whole point of the shape. An exported ErrPskNonceLength declared
// here would be a second public declaration site for a name the validation plan also
// declares, the two would not be the same value, and a caller matching one would
// silently stop matching the other -- which is the failure errors_key_schedule.go's own
// header warns about. A name that cannot be reached from outside this package cannot be
// depended on from outside it either, so the swap costs nobody else anything.
//
// The swap itself is mechanical: wrap each detail in ValSem(ValSem401, ...) or
// ValSem(ValSem402, ...) with the catalogue's sentinel as the detail, which is what the
// plan's body says and what makes errors.Is and CodeOf both hold. The messages here are
// the catalogue's own reason strings so that the text does not move either.
//
// The moment that swap is owed is not left to anybody's memory. ValSem, ValSem401,
// ValSem402, ErrPskNonceLength and ErrPskType are all listed in
// crossPlanSymbolsNotYetLanded in key_schedule_deps_test.go, and that gate fails on the
// commit that lands them, naming each one.
var (
	// errPskNonceLength is ValSem401. RFC 9420 section 8.4 requires psk_nonce to be a
	// fresh random value of KDF.Nh bytes, and a shorter one is not merely out of spec:
	// psk_nonce is the whole of what separates two uses of one pre shared key, so a
	// nonce an attacker can shorten is a nonce an attacker can collide.
	errPskNonceLength = errors.New("mls: psk: nonce length does not match the ciphersuite KDF output")

	// errPskType is ValSem402, which covers both a psktype outside the registry and a
	// resumption usage this profile does not implement. One code covers both because
	// they are one refusal from the receiver's point of view: this is not a
	// PreSharedKeyId it is willing to act on.
	errPskType = errors.New("mls: psk: resumption usage is not permitted here")
)

// PskType is the RFC 9420 section 8.4 PSKType enum. Zero is reserved and every value
// outside the two below is unregistered; both are refused rather than defaulted, for the
// reason the ciphersuite registry gives -- a default would let a peer's unsupported arm
// be silently read as one it never sent.
type PskType uint8

const (
	PskTypeExternal   PskType = 1
	PskTypeResumption PskType = 2
)

// ResumptionPskUsage is the RFC 9420 section 8.4 ResumptionPSKUsage enum. It is carried
// on the wire as a plain octet and judged separately, because decoding and accepting are
// different questions: a value this profile refuses still has to decode for the refusal
// to be able to name it.
type ResumptionPskUsage uint8

const (
	ResumptionPskUsageApplication ResumptionPskUsage = 1
	ResumptionPskUsageReInit      ResumptionPskUsage = 2
	ResumptionPskUsageBranch      ResumptionPskUsage = 3
)

// PreSharedKeyId identifies one pre shared key. The RFC's select() arms are flattened
// into one struct rather than modelled as a sum type, because the encoding is only ever
// produced and consumed here and the discriminant is already a field. What the
// flattening costs is that a value can hold fields its own arm does not encode, so the
// codec below is careful in both directions: MarshalMLS writes only the fields of the arm
// its discriminant names, and UnmarshalMLS clears the ones it did not read.
type PreSharedKeyId struct {
	PskType    PskType
	PskId      []byte
	Usage      ResumptionPskUsage
	PskGroupId []byte
	PskEpoch   uint64
	PskNonce   []byte
}

// MarshalMLS writes the id inline into a writer the caller owns and with no framing of
// its own, which is exactly what PSKLabel and GroupSecrets.psks<V> need -- a length
// prefix added here would be invisible to a caller reading only its own bytes and fatal
// to the psk_secret every member derives from them.
//
// The leaf writes return nothing and are no ops after the first failure (C2); the buffer
// error is collected by syntax.Marshal at Bytes. The error return carries the one
// semantic refusal this encoder has, an arm it cannot represent. Dropping that refusal
// would not be cosmetic: the discriminant octet and the nonce would still be written, so
// the result is a short but structurally plausible id that hashes into psk_input as
// though it were whole, and every member receiving it derives a psk_secret from bytes
// describing a key nobody named.
func (self *PreSharedKeyId) MarshalMLS(w *syntax.Writer) error {
	w.WriteUint8(uint8(self.PskType))
	switch self.PskType {
	case PskTypeExternal:
		w.WriteOpaque(self.PskId)
	case PskTypeResumption:
		w.WriteUint8(uint8(self.Usage))
		w.WriteOpaque(self.PskGroupId)
		w.WriteUint64(self.PskEpoch)
	default:
		return fmt.Errorf("%w: psktype %d", errPskType, self.PskType)
	}
	w.WriteOpaque(self.PskNonce)
	return nil
}

// UnmarshalMLS decodes exactly one id and leaves the rest of the reader alone, which is
// what a psks<V> vector and a PSKLabel preimage both depend on: eating the tail here
// would eat the next id, or the joiner secret sitting behind it. Full consumption of a
// standalone encoding is enforced one layer up, by syntax.Unmarshal.
//
// An unregistered psktype is a decode error rather than a value carried through. The
// alternative -- decode it, keep the octet, refuse later -- sounds more tolerant and is
// not: the arm decides how many bytes follow it, so an implementation that does not know
// the arm does not know where the id ends, and anything it does with the bytes after the
// discriminant is a guess.
//
// Nothing is assigned until every field has been read, and every field is assigned once
// they have. Both halves matter and they fail differently. A decoder that assigned as it
// read would leave a refused decode holding some fields from the new input and the rest
// from whatever the caller's value held before -- not a mangled struct anybody would
// notice, but a well formed PreSharedKeyId naming a key that was never sent. A decoder
// that assigned only the fields of the arm it read would leave the OTHER arm's fields
// behind on a reused receiver: decode a resumption id, then an external one into the same
// value, and PskGroupId and PskEpoch still describe the first.
func (self *PreSharedKeyId) UnmarshalMLS(r *syntax.Reader) error {
	typeOctet, err := r.ReadUint8()
	if err != nil {
		return fmt.Errorf("mls: psk type: %w", err)
	}
	var (
		pskType    = PskType(typeOctet)
		pskId      []byte
		usage      ResumptionPskUsage
		pskGroupId []byte
		pskEpoch   uint64
	)
	switch pskType {
	case PskTypeExternal:
		if pskId, err = r.ReadOpaque(); err != nil {
			return fmt.Errorf("mls: psk id: %w", err)
		}
	case PskTypeResumption:
		usageOctet, usageErr := r.ReadUint8()
		if usageErr != nil {
			return fmt.Errorf("mls: psk usage: %w", usageErr)
		}
		usage = ResumptionPskUsage(usageOctet)
		if pskGroupId, err = r.ReadOpaque(); err != nil {
			return fmt.Errorf("mls: psk group id: %w", err)
		}
		if pskEpoch, err = r.ReadUint64(); err != nil {
			return fmt.Errorf("mls: psk epoch: %w", err)
		}
	default:
		return fmt.Errorf("%w: psktype %d", errPskType, pskType)
	}
	pskNonce, err := r.ReadOpaque()
	if err != nil {
		return fmt.Errorf("mls: psk nonce: %w", err)
	}
	self.PskType = pskType
	self.PskId = pskId
	self.Usage = usage
	self.PskGroupId = pskGroupId
	self.PskEpoch = pskEpoch
	self.PskNonce = pskNonce
	return nil
}

// the C1 pin: drift between this type and the one codec convention fails at build.
var _ syntax.Codec = (*PreSharedKeyId)(nil)

// Validate is ValSem401 (nonce length) and ValSem402 (type and resumption usage).
//
// The nonce length is read off the provider rather than compared against 32, because
// KDF.Nh is a property of the ciphersuite and the two suites registered today happen to
// agree on it. A literal here would be indistinguishable from the derivation until the
// first suite with a wider hash arrives, at which point it would accept a nonce half the
// length the RFC requires and nothing in this package would say so.
//
// ValSem402 refuses ReInit and Branch. Both name features the v1 profile does not
// implement, and the RFC permits either only in a context this implementation never
// constructs -- a ReInit commit, a Branch welcome. Accepting one here would let a
// resumption secret from a group nobody re-initialised be mixed into an epoch, which is
// the confusion the usage field exists to prevent.
func (self *PreSharedKeyId) Validate(crypto CryptoProvider) error {
	if len(self.PskNonce) != crypto.HashSize() {
		return fmt.Errorf("%w: %d bytes, want %d",
			errPskNonceLength, len(self.PskNonce), crypto.HashSize())
	}
	switch self.PskType {
	case PskTypeExternal:
		return nil
	case PskTypeResumption:
		if self.Usage != ResumptionPskUsageApplication {
			return fmt.Errorf("%w: resumption usage %d", errPskType, self.Usage)
		}
		return nil
	}
	return fmt.Errorf("%w: psktype %d", errPskType, self.PskType)
}
