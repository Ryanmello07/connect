// The RFC 9420 section 2.1.2 variable length integer, and the length limits every
// variable length read in this package is bounded by.
package syntax

const (
	// the largest value the two bit prefixed varint can carry
	MaxVarint uint32 = 1<<30 - 1
	// the default cap on any single variable length field, spec A section 5.8
	MaxVectorLength int = 1 << 20
	// the cap raised for the ratchet tree only; tree_sync and group decode through
	// UnmarshalLimit with this value, everything else uses the default
	MaxRatchetTreeLength int = 1 << 24
)
