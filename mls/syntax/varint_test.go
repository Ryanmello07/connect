// The RFC 9420 section 2.1.2 varint, both directions. The encoder emits exactly one
// form per value and the decoder accepts exactly that form, because a decoder that
// accepts a second encoding of one length turns a signed structure into a malleable
// one.
package syntax

import (
	"bytes"
	"errors"
	"testing"
)

// the boundary of every prefix width, from rfc 9420 section 2.1.2
var varintBoundaries = []struct {
	value   uint32
	encoded []byte
}{
	{0, []byte{0x00}},
	{13, []byte{0x0d}},
	{54, []byte{0x36}},
	{63, []byte{0x3f}},
	{64, []byte{0x40, 0x40}},
	{389, []byte{0x41, 0x85}},
	{2730, []byte{0x4a, 0xaa}},
	{4095, []byte{0x4f, 0xff}},
	{16383, []byte{0x7f, 0xff}},
	{16384, []byte{0x80, 0x00, 0x40, 0x00}},
	{48879, []byte{0x80, 0x00, 0xbe, 0xef}},
	{57005, []byte{0x80, 0x00, 0xde, 0xad}},
	{1073741823, []byte{0xbf, 0xff, 0xff, 0xff}},
}

// TestWriteVarintIsMinimal asserts WriteVarint emits exactly the minimal encoding
// at every prefix width boundary: the widest value still using the narrower form
// immediately beside the narrowest value that needs the wider one, on both sides
// of every transition, plus 0 and MaxVarint at the extremes. Bytes are checked
// against concrete literals, not merely for the absence of an error.
func TestWriteVarintIsMinimal(t *testing.T) {
	for _, c := range varintBoundaries {
		w := NewWriter()
		w.WriteVarint(c.value)
		out, err := w.Bytes()
		if err != nil {
			t.Fatalf("value %d: unexpected error %v", c.value, err)
		}
		if !bytes.Equal(out, c.encoded) {
			t.Errorf("value %d encoded to %x, want %x", c.value, out, c.encoded)
		}
	}
}

// TestWriteVarintRejectsValuesAboveTheRange asserts that any value past MaxVarint —
// starting at MaxVarint+1, the first rejected value — sets the sticky
// ErrVarintOverflow and appends zero bytes, never a partial write of the value it
// refused to encode.
func TestWriteVarintRejectsValuesAboveTheRange(t *testing.T) {
	for _, v := range []uint32{MaxVarint + 1, 0x40000000, 0x7fffffff, 0xffffffff} {
		w := NewWriter()
		w.WriteVarint(v)
		out, err := w.Bytes()
		if !errors.Is(err, ErrVarintOverflow) {
			t.Errorf("value %d gave %v, want ErrVarintOverflow", v, err)
		}
		if out != nil {
			t.Errorf("value %d: Bytes returned %x alongside an error, want nil", v, out)
		}
		if w.Len() != 0 {
			t.Errorf("value %d: Len is %d, want 0: an overflow must append nothing", v, w.Len())
		}
	}
}
