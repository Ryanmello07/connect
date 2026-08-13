// Writer behaviour: big endian integers, unprefixed raw bytes, and the sticky error
// that makes a single check at Bytes sufficient.
package syntax

import (
	"bytes"
	"errors"
	"testing"
)

// TestWriterIntegersAreBigEndian asserts WriteUint8/16/32/64 each append their value
// most significant byte first, with no padding or alignment between fields.
func TestWriterIntegersAreBigEndian(t *testing.T) {
	w := NewWriter()
	w.WriteUint8(0x2a)
	w.WriteUint16(0x0102)
	w.WriteUint32(0x01020304)
	w.WriteUint64(0x0102030405060708)
	out, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{
		0x2a,
		0x01, 0x02,
		0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	if !bytes.Equal(out, want) {
		t.Errorf("encoded %x, want %x", out, want)
	}
	if w.Len() != len(want) {
		t.Errorf("Len is %d, want %d", w.Len(), len(want))
	}
}

// TestWriterRawTakesNoPrefix asserts WriteRaw appends exactly the given bytes with no
// length prefix, and that a nil or empty slice writes nothing.
func TestWriterRawTakesNoPrefix(t *testing.T) {
	w := NewWriter()
	w.WriteRaw([]byte{0xaa, 0xbb, 0xcc})
	w.WriteRaw(nil)
	w.WriteRaw([]byte{})
	out, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, []byte{0xaa, 0xbb, 0xcc}) {
		t.Errorf("encoded %x, want aabbcc", out)
	}
}

// TestWriterErrorIsStickyAndSuppressesLaterWrites asserts the first error set wins over
// later ones, that Err and Bytes both report it, that Bytes hands back nil bytes
// alongside a non nil error, and that a write after an error is a no op — exercised
// through all six write methods (WriteUint8, WriteUint16, WriteUint32, WriteUint64,
// WriteRaw, WriteVarint), since each carries the identical error guard at a distinct
// call site.
func TestWriterErrorIsStickyAndSuppressesLaterWrites(t *testing.T) {
	w := NewWriter()
	w.WriteUint8(0x01)
	w.setErr(ErrLengthExceedsMax)
	w.setErr(ErrTruncated)
	w.WriteUint16(0xffff)
	w.WriteUint32(0xffffffff)
	w.WriteUint64(0xffffffffffffffff)
	w.WriteRaw([]byte{0xff, 0xff, 0xff})
	w.WriteVarint(0x2a)
	if !errors.Is(w.Err(), ErrLengthExceedsMax) {
		t.Errorf("Err is %v, want the first error ErrLengthExceedsMax", w.Err())
	}
	out, err := w.Bytes()
	if !errors.Is(err, ErrLengthExceedsMax) {
		t.Errorf("Bytes returned %v, want ErrLengthExceedsMax", err)
	}
	if out != nil {
		t.Errorf("Bytes returned %x alongside an error, want nil", out)
	}
	if w.Len() != 1 {
		t.Errorf("Len is %d, want 1: writes after an error must be no ops", w.Len())
	}
}

// TestNewWriterLimitRejectsNegative asserts a negative limit sets ErrNegativeLength as
// the sticky error at construction time, before any write, and that a write on such a
// Writer is a no op just like any other post error write.
func TestNewWriterLimitRejectsNegative(t *testing.T) {
	w := NewWriterLimit(-1)
	if !errors.Is(w.Err(), ErrNegativeLength) {
		t.Errorf("Err is %v, want ErrNegativeLength", w.Err())
	}
	w.WriteUint8(0x01)
	if w.Len() != 0 {
		t.Errorf("Len is %d, want 0: a write on a negative limit Writer must be a no op", w.Len())
	}
	out, err := w.Bytes()
	if !errors.Is(err, ErrNegativeLength) {
		t.Errorf("Bytes returned %v, want ErrNegativeLength", err)
	}
	if out != nil {
		t.Errorf("Bytes returned %x alongside an error, want nil", out)
	}
}

// TestWriterLimitIsCarried asserts NewWriter carries the package default MaxVectorLength
// and NewWriterLimit carries whatever limit the caller passes, such as MaxRatchetTreeLength.
func TestWriterLimitIsCarried(t *testing.T) {
	if NewWriter().MaxVectorLength() != MaxVectorLength {
		t.Errorf("NewWriter did not take the default limit")
	}
	if NewWriterLimit(MaxRatchetTreeLength).MaxVectorLength() != MaxRatchetTreeLength {
		t.Errorf("NewWriterLimit did not take the given limit")
	}
}

// TestWriteOpaqueTreatsNilAndEmptyAlike asserts a nil slice and a zero length,
// non nil slice both encode to the single zero length varint octet: opaque x<V>
// has no representation for "absent", only for "zero bytes", so the two Go values
// must collapse to the same wire form.
func TestWriteOpaqueTreatsNilAndEmptyAlike(t *testing.T) {
	for _, in := range [][]byte{nil, {}} {
		w := NewWriter()
		w.WriteOpaque(in)
		out, err := w.Bytes()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(out, []byte{0x00}) {
			t.Errorf("empty opaque encoded to %x, want 00", out)
		}
	}
}

// TestWriteOpaqueUsesTheVarintPrefix asserts WriteOpaque prefixes the body with
// exactly the RFC 9420 section 2.1.2 varint encoding of its length, at each width
// the varint format uses: one octet up to 63, two octets from 64, four octets
// from 16384.
func TestWriteOpaqueUsesTheVarintPrefix(t *testing.T) {
	cases := []struct {
		length int
		prefix []byte
	}{
		{1, []byte{0x01}},
		{63, []byte{0x3f}},
		{64, []byte{0x40, 0x40}},
		{16383, []byte{0x7f, 0xff}},
		{16384, []byte{0x80, 0x00, 0x40, 0x00}},
	}
	for _, c := range cases {
		body := bytes.Repeat([]byte{0x11}, c.length)
		w := NewWriter()
		w.WriteOpaque(body)
		out, err := w.Bytes()
		if err != nil {
			t.Fatalf("length %d: unexpected error %v", c.length, err)
		}
		want := append(append([]byte{}, c.prefix...), body...)
		if !bytes.Equal(out, want) {
			t.Errorf("length %d encoded to %x..., want prefix %x", c.length, out[:len(c.prefix)+1], c.prefix)
		}
	}
}

// TestWriteOpaqueRefusesToExceedTheLimit asserts a body longer than the Writer's
// configured maximum vector length sets the sticky ErrLengthExceedsMax instead of
// silently accepting an oversized field.
func TestWriteOpaqueRefusesToExceedTheLimit(t *testing.T) {
	w := NewWriterLimit(16)
	w.WriteOpaque(bytes.Repeat([]byte{0x11}, 17))
	if _, err := w.Bytes(); !errors.Is(err, ErrLengthExceedsMax) {
		t.Errorf("over limit write gave %v, want ErrLengthExceedsMax", err)
	}
}

// TestWriteOpaqueLPUsesAFixedThirtyTwoBitPrefix asserts the length prefix is
// always four big endian octets regardless of how short the body is, unlike the
// varint form whose width tracks the value: a nil body and an empty one both
// encode to four zero octets, so the record layer can locate a field's body at a
// fixed offset without first parsing a variable width prefix.
func TestWriteOpaqueLPUsesAFixedThirtyTwoBitPrefix(t *testing.T) {
	cases := []struct {
		body []byte
		want []byte
	}{
		{nil, []byte{0x00, 0x00, 0x00, 0x00}},
		{[]byte{}, []byte{0x00, 0x00, 0x00, 0x00}},
		{[]byte{0xaa}, []byte{0x00, 0x00, 0x00, 0x01, 0xaa}},
		{[]byte{0xaa, 0xbb}, []byte{0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb}},
	}
	for _, c := range cases {
		w := NewWriter()
		w.WriteOpaqueLP(c.body)
		out, err := w.Bytes()
		if err != nil {
			t.Fatalf("body %x: unexpected error %v", c.body, err)
		}
		if !bytes.Equal(out, c.want) {
			t.Errorf("body %x encoded to %x, want %x", c.body, out, c.want)
		}
	}
}

// the two prefix forms must never be confusable, because connect/message uses LP
// for records and connect/mls uses <V> for MLS structures and one codec serves both
func TestLPAndVarintPrefixesAreDistinct(t *testing.T) {
	for _, body := range [][]byte{nil, {0xaa}, bytes.Repeat([]byte{0x11}, 200)} {
		lp := NewWriter()
		lp.WriteOpaqueLP(body)
		lpBytes, err := lp.Bytes()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		v := NewWriter()
		v.WriteOpaque(body)
		vBytes, err := v.Bytes()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if bytes.Equal(lpBytes, vBytes) {
			t.Errorf("body %x encoded identically under both prefix forms: %x", body, lpBytes)
		}
	}
}

// the property the three case check above only spot checks, swept across every
// varint width boundary. The three bodies it uses are 0, 1 and 200 bytes, all of
// which fall in the regime where the two encodings differ in total length — one or
// two prefix octets against LP's four — so the check cannot fail whatever the
// prefixes say, and it never reaches the interesting case. From 16384 bytes up both
// forms are four octets and the encodings are the same total length, and
// distinctness rests entirely on the first octet: LP's is the length's top byte,
// which cannot exceed 0x3f because WriteOpaque refuses anything above MaxVarint, so
// its top two bits are 00, while the four octet varint's first octet carries the
// prefix 10. This asserts distinctness directly and also asserts that the equal
// length regime was actually reached, so the sweep cannot quietly degenerate into
// the trivial one.
func TestLPAndVarintPrefixesNeverCoincideAcrossWidths(t *testing.T) {
	lengths := []int{}
	// every length up to just past the one octet boundary, then each width boundary
	// and its neighbours, then the top of the range WriteOpaque accepts
	for n := 0; n <= 300; n += 1 {
		lengths = append(lengths, n)
	}
	lengths = append(lengths,
		16382, 16383, 16384, 16385, 16386,
		65535, 65536, 100000,
		MaxVectorLength-1, MaxVectorLength,
	)
	sameLengthCases := 0
	for _, n := range lengths {
		body := bytes.Repeat([]byte{0x5a}, n)
		lp := NewWriter()
		lp.WriteOpaqueLP(body)
		lpBytes, err := lp.Bytes()
		if err != nil {
			t.Fatalf("length %d: unexpected error %v", n, err)
		}
		v := NewWriter()
		v.WriteOpaque(body)
		vBytes, err := v.Bytes()
		if err != nil {
			t.Fatalf("length %d: unexpected error %v", n, err)
		}
		if bytes.Equal(lpBytes, vBytes) {
			t.Errorf("length %d encoded identically under both prefix forms", n)
		}
		if len(lpBytes) == len(vBytes) {
			sameLengthCases += 1
			// the encodings agree on every byte but the prefix here, so the whole
			// property rests on the first octet's top two bits
			if lpBytes[0]>>6 == vBytes[0]>>6 {
				t.Errorf("length %d gave both forms the same two prefix bits %#02b", n, lpBytes[0]>>6)
			}
		}
	}
	if sameLengthCases == 0 {
		t.Errorf("no length produced two encodings of equal total length, so the interesting regime was never reached")
	}
}
