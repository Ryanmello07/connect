// Reader behaviour: big endian integers, copied raw bytes, a cursor that a failed
// read never advances, the full consumption rule, and a limit-taking constructor
// that validates rather than deferring, matching Writer's precedent in encode.go.
package syntax

import (
	"bytes"
	"errors"
	"testing"
)

// TestReaderIntegersAreBigEndian asserts ReadUint8/16/32/64 each read their value
// most significant byte first, with no padding or alignment between fields, and
// that Done reports no error once every byte has been consumed.
func TestReaderIntegersAreBigEndian(t *testing.T) {
	r := NewReader([]byte{
		0x2a,
		0x01, 0x02,
		0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	})
	if v, err := r.ReadUint8(); err != nil || v != 0x2a {
		t.Fatalf("ReadUint8 gave %#x, %v", v, err)
	}
	if v, err := r.ReadUint16(); err != nil || v != 0x0102 {
		t.Fatalf("ReadUint16 gave %#x, %v", v, err)
	}
	if v, err := r.ReadUint32(); err != nil || v != 0x01020304 {
		t.Fatalf("ReadUint32 gave %#x, %v", v, err)
	}
	if v, err := r.ReadUint64(); err != nil || v != 0x0102030405060708 {
		t.Fatalf("ReadUint64 gave %#x, %v", v, err)
	}
	if err := r.Done(); err != nil {
		t.Errorf("Done gave %v, want nil", err)
	}
}

// TestReaderTruncatedReadDoesNotAdvance asserts that when a read has too few bytes
// left to satisfy it, it reports ErrTruncated and leaves Offset unchanged — checked
// across ReadUint8, ReadUint16, ReadUint32, ReadUint64 and ReadRaw, since each
// carries the identical bounds check at a distinct call site.
func TestReaderTruncatedReadDoesNotAdvance(t *testing.T) {
	cases := []struct {
		input []byte
		read  func(*Reader) error
	}{
		{[]byte{}, func(r *Reader) error { _, err := r.ReadUint8(); return err }},
		{[]byte{0x01}, func(r *Reader) error { _, err := r.ReadUint16(); return err }},
		{[]byte{0x01, 0x02, 0x03}, func(r *Reader) error { _, err := r.ReadUint32(); return err }},
		{[]byte{0x01, 0x02, 0x03, 0x04}, func(r *Reader) error { _, err := r.ReadUint64(); return err }},
		{[]byte{0x01}, func(r *Reader) error { _, err := r.ReadRaw(2); return err }},
	}
	for i, c := range cases {
		r := NewReader(c.input)
		if err := c.read(r); !errors.Is(err, ErrTruncated) {
			t.Errorf("case %d gave %v, want ErrTruncated", i, err)
		}
		if r.Offset() != 0 {
			t.Errorf("case %d advanced the cursor to %d on a failed read", i, r.Offset())
		}
	}
}

// TestReaderRawReturnsACopy asserts ReadRaw's result does not alias the input
// slice: mutating the returned bytes must not change the source buffer.
func TestReaderRawReturnsACopy(t *testing.T) {
	input := []byte{0xaa, 0xbb, 0xcc}
	r := NewReader(input)
	out, err := r.ReadRaw(3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out[0] = 0xff
	if input[0] != 0xaa {
		t.Errorf("ReadRaw aliased the input; mutating the result changed the source buffer")
	}
	if !bytes.Equal(out, []byte{0xff, 0xbb, 0xcc}) {
		t.Errorf("copy is %x, want ffbbcc", out)
	}
}

// TestReaderRawRejectsANegativeLength asserts ReadRaw(-1) reports ErrNegativeLength
// rather than panicking or underflowing a slice bound.
func TestReaderRawRejectsANegativeLength(t *testing.T) {
	r := NewReader([]byte{0xaa})
	if _, err := r.ReadRaw(-1); !errors.Is(err, ErrNegativeLength) {
		t.Errorf("ReadRaw(-1) gave %v, want ErrNegativeLength", err)
	}
}

// TestReaderDoneRejectsTrailingBytes asserts Done reports ErrTrailingBytes when
// bytes remain after a decode, and that Remaining and Empty still report the true
// state of the cursor rather than being disturbed by the failed Done call.
func TestReaderDoneRejectsTrailingBytes(t *testing.T) {
	r := NewReader([]byte{0x01, 0x02})
	if _, err := r.ReadUint8(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := r.Done(); !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("Done gave %v, want ErrTrailingBytes", err)
	}
	if r.Remaining() != 1 || r.Empty() {
		t.Errorf("Remaining is %d and Empty is %v, want 1 and false", r.Remaining(), r.Empty())
	}
}

// TestReaderLimitIsCarried asserts NewReader carries the package default
// MaxVectorLength and NewReaderLimit carries whatever limit the caller passes,
// such as MaxRatchetTreeLength.
func TestReaderLimitIsCarried(t *testing.T) {
	if NewReader(nil).MaxVectorLength() != MaxVectorLength {
		t.Errorf("NewReader did not take the default limit")
	}
	if NewReaderLimit(nil, MaxRatchetTreeLength).MaxVectorLength() != MaxRatchetTreeLength {
		t.Errorf("NewReaderLimit did not take the given limit")
	}
}

// TestNewReaderLimitRejectsNegative asserts a negative limit sets ErrNegativeLength
// as a sticky construction time error: every subsequent read reports it
// immediately without consuming input, and Done reports it too. This mirrors the
// precedent set for NewWriterLimit in encode.go — validate at construction, do not
// defer — because ErrNegativeLength's own doc comment claims it fires on exactly
// this misuse, on both halves of the codec. Checked across all five read methods
// (ReadUint8, ReadUint16, ReadUint32, ReadUint64, ReadRaw), since the sticky guard
// sits at a distinct call site in each and any one of them could be missed.
func TestNewReaderLimitRejectsNegative(t *testing.T) {
	r := NewReaderLimit([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, -1)
	if _, err := r.ReadUint8(); !errors.Is(err, ErrNegativeLength) {
		t.Errorf("ReadUint8 gave %v, want ErrNegativeLength", err)
	}
	if _, err := r.ReadUint16(); !errors.Is(err, ErrNegativeLength) {
		t.Errorf("ReadUint16 gave %v, want ErrNegativeLength", err)
	}
	if _, err := r.ReadUint32(); !errors.Is(err, ErrNegativeLength) {
		t.Errorf("ReadUint32 gave %v, want ErrNegativeLength", err)
	}
	if _, err := r.ReadUint64(); !errors.Is(err, ErrNegativeLength) {
		t.Errorf("ReadUint64 gave %v, want ErrNegativeLength", err)
	}
	if _, err := r.ReadRaw(1); !errors.Is(err, ErrNegativeLength) {
		t.Errorf("ReadRaw gave %v, want ErrNegativeLength", err)
	}
	if r.Offset() != 0 {
		t.Errorf("Offset is %d, want 0: a read reporting the construction error must not consume input", r.Offset())
	}
	if err := r.Done(); !errors.Is(err, ErrNegativeLength) {
		t.Errorf("Done gave %v, want ErrNegativeLength", err)
	}
}

// TestReaderLatchesAFailureAsSticky asserts that once a read fails, that failure
// is latched into the Reader: a caller that ignores the error and issues a
// second, smaller read against the same still-unconsumed bytes must not silently
// succeed and reinterpret them as a different field. It must instead report the
// same, first error, and Done must report it too rather than treating the
// (partially, wrongly) advanced input as fully consumed.
func TestReaderLatchesAFailureAsSticky(t *testing.T) {
	r := NewReader([]byte{0x01, 0x02})
	if _, err := r.ReadUint32(); !errors.Is(err, ErrTruncated) {
		t.Fatalf("ReadUint32 gave %v, want ErrTruncated", err)
	}
	// The two bytes above are enough to satisfy ReadUint16 on their own: without
	// latching, this call would silently succeed and return 0x0102.
	if v, err := r.ReadUint16(); !errors.Is(err, ErrTruncated) {
		t.Errorf("ReadUint16 after an ignored ErrTruncated gave value %#x, err %v; want the latched ErrTruncated and no value", v, err)
	}
	if r.Offset() != 0 {
		t.Errorf("Offset is %d, want 0: a read blocked by the latched error must not consume input", r.Offset())
	}
	if err := r.Done(); !errors.Is(err, ErrTruncated) {
		t.Errorf("Done gave %v, want the latched ErrTruncated", err)
	}
}

// TestReadOpaqueRoundTripsAndCopies asserts a value ReadOpaque decodes from
// WriteOpaque's own output is byte identical to the original, that Done reports
// full consumption afterward, and that the returned slice does not alias the
// Reader's input: mutating the result must not change the source bytes.
func TestReadOpaqueRoundTripsAndCopies(t *testing.T) {
	body := bytes.Repeat([]byte{0x11}, 100)
	w := NewWriter()
	w.WriteOpaque(body)
	encoded, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := NewReader(encoded)
	got, err := r.ReadOpaque()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("decoded %x, want %x", got, body)
	}
	if err := r.Done(); err != nil {
		t.Errorf("Done gave %v", err)
	}
	got[0] = 0xff
	if encoded[2] != 0x11 {
		t.Errorf("ReadOpaque aliased the input")
	}
}

// TestReadOpaqueEmptyIsNonNil asserts decoding the single zero length octet gives
// a zero length slice that is not nil: opaque x<V> encodes "zero bytes" but has
// no wire representation for "absent", so ReadOpaque must never hand back nil.
func TestReadOpaqueEmptyIsNonNil(t *testing.T) {
	r := NewReader([]byte{0x00})
	got, err := r.ReadOpaque()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Errorf("empty opaque decoded to nil, want a zero length non nil slice")
	}
	if len(got) != 0 {
		t.Errorf("empty opaque decoded to %x", got)
	}
}

// TestReadOpaqueChecksTheLimitThenTheInput asserts ReadOpaque rejects a declared
// length with the correct, distinguishable sentinel for each way it can be
// invalid: over the configured maximum, over the bytes actually remaining (both
// when the varint claims more input than exists at all, and when it claims more
// than trails the prefix), and a non minimally encoded varint prefix rejected by
// ReadVarint itself before takeLength ever runs.
func TestReadOpaqueChecksTheLimitThenTheInput(t *testing.T) {
	cases := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{"length above the limit", []byte{0xbf, 0xff, 0xff, 0xff}, ErrLengthExceedsMax},
		{"length above the remaining input", []byte{0x40, 0x40, 0x11, 0x11}, ErrLengthExceedsInput},
		{"prefix only", []byte{0x05}, ErrLengthExceedsInput},
		{"non minimal prefix", []byte{0x40, 0x00}, ErrVarintNotMinimal},
	}
	for _, c := range cases {
		r := NewReader(c.input)
		if _, err := r.ReadOpaque(); !errors.Is(err, c.wantErr) {
			t.Errorf("%s gave %v, want %v", c.name, err, c.wantErr)
		}
	}
}

// TestReadOpaqueRejectsAHostileLengthWithoutAllocating is the security property
// the plan calls out by name: a four byte input can declare a varint length up to
// 0x3fffffff (about 1 GiB), far more than MaxVectorLength (1 MiB) and far more
// than the four bytes actually present. If ReadOpaque ever allocated the declared
// length before validating it against the maximum and the remaining input, this
// test would make a gigabyte scale allocation on every one of its 200 runs.
// testing.AllocsPerRun measures that directly instead of merely being slow to
// fail: a Reader construction is the only allocation expected, so the count
// must stay small and constant, never scaled to the attacker supplied length.
func TestReadOpaqueRejectsAHostileLengthWithoutAllocating(t *testing.T) {
	input := []byte{0xbf, 0xff, 0xff, 0xff} // declares length 0x3fffffff, ~1 GiB
	if _, err := NewReader(input).ReadOpaque(); !errors.Is(err, ErrLengthExceedsMax) {
		t.Fatalf("got %v, want ErrLengthExceedsMax", err)
	}
	allocs := testing.AllocsPerRun(200, func() {
		r := NewReader(input)
		_, _ = r.ReadOpaque()
	})
	if allocs > 4 {
		t.Errorf("ReadOpaque allocated %.1f times per run rejecting a hostile length, want a small constant count, not one sized to the declared ~1 GiB length", allocs)
	}
}

// TestOpaqueRoundTripsAcrossVarintWidthBoundaries asserts that at every length
// where the varint prefix's width changes — 0, 1, 63, 64, 16383, 16384 — a value
// WriteOpaque emits decodes back through ReadOpaque byte identical to the
// original, with zero the boundary case people forget: an empty opaque field is
// not a special case in the encoding, only in whether the result is nil.
func TestOpaqueRoundTripsAcrossVarintWidthBoundaries(t *testing.T) {
	for _, length := range []int{0, 1, 63, 64, 16383, 16384} {
		body := bytes.Repeat([]byte{0x11}, length)
		w := NewWriter()
		w.WriteOpaque(body)
		encoded, err := w.Bytes()
		if err != nil {
			t.Fatalf("length %d: unexpected error %v", length, err)
		}
		r := NewReader(encoded)
		got, err := r.ReadOpaque()
		if err != nil {
			t.Fatalf("length %d: unexpected error %v", length, err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("length %d: decoded %x, want %x", length, got, body)
		}
		if got == nil {
			t.Errorf("length %d: decoded to nil, want a non nil slice", length)
		}
		if err := r.Done(); err != nil {
			t.Errorf("length %d: Done gave %v", length, err)
		}
	}
}

// TestOpaqueRoundTripsTheEmptyStringFromANilWrite asserts the specific boundary
// the brief calls out by name: writing a nil slice through WriteOpaque and
// reading it back through ReadOpaque must round trip to a zero length, non nil
// slice, not to nil and not to an error.
func TestOpaqueRoundTripsTheEmptyStringFromANilWrite(t *testing.T) {
	w := NewWriter()
	w.WriteOpaque(nil)
	encoded, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := NewReader(encoded)
	got, err := r.ReadOpaque()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("decoded %#v, want a zero length non nil slice", got)
	}
	if err := r.Done(); err != nil {
		t.Errorf("Done gave %v", err)
	}
}
