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

// WriteVarint appends v as the RFC 9420 section 2.1.2 variable length integer:
// exactly one octet for 0..63, two for 64..16383, four for 16384..MaxVarint. The
// two most significant bits of the first octet are the prefix — the base 2
// logarithm of the octet count — so the widths never overlap and no value has a
// second valid encoding. Values above MaxVarint set the sticky ErrVarintOverflow
// and append nothing, matching every other Writer method's no op after failure.
func (self *Writer) WriteVarint(v uint32) {
	if self.err != nil {
		return
	}
	switch {
	case v <= 0x3f:
		self.bs = append(self.bs, byte(v))
	case v <= 0x3fff:
		self.bs = append(self.bs, byte(v>>8)|0x40, byte(v))
	case v <= MaxVarint:
		self.bs = append(self.bs, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		self.setErr(ErrVarintOverflow)
	}
}
