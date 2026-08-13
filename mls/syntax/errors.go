// The package's complete error contract. Every failure path returns one of these
// sentinels, possibly joined with another for context. Callers compare with
// errors.Is and never parse a string, so the messages are for humans only.
package syntax

import "errors"

var (
	ErrTruncated             = errors.New("mls syntax: input truncated")
	ErrTrailingBytes         = errors.New("mls syntax: trailing bytes after top level value")
	ErrVarintReserved        = errors.New("mls syntax: varint prefix 0b11 is reserved")
	ErrVarintNotMinimal      = errors.New("mls syntax: varint is not minimally encoded")
	ErrVarintOverflow        = errors.New("mls syntax: varint value exceeds 2^30-1")
	ErrLengthExceedsInput    = errors.New("mls syntax: declared length exceeds remaining input")
	ErrLengthExceedsMax      = errors.New("mls syntax: declared length exceeds the configured maximum")
	ErrOptionalPresence      = errors.New("mls syntax: optional presence octet is neither 0 nor 1")
	ErrZeroLengthElement     = errors.New("mls syntax: vector element consumed zero bytes")
	ErrNegativeLength        = errors.New("mls syntax: negative length")
	ErrRoundTripNotByteExact = errors.New("mls syntax: re-encoding an accepted value did not reproduce its bytes")
	ErrRoundTripNotStable    = errors.New("mls syntax: decoding a re-encoded value did not reproduce the value")
)
