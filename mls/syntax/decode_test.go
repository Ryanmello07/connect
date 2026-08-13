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
// this misuse, on both halves of the codec.
func TestNewReaderLimitRejectsNegative(t *testing.T) {
	r := NewReaderLimit([]byte{0x01, 0x02}, -1)
	if _, err := r.ReadUint8(); !errors.Is(err, ErrNegativeLength) {
		t.Errorf("ReadUint8 gave %v, want ErrNegativeLength", err)
	}
	if r.Offset() != 0 {
		t.Errorf("Offset is %d, want 0: a read reporting the construction error must not consume input", r.Offset())
	}
	if _, err := r.ReadRaw(1); !errors.Is(err, ErrNegativeLength) {
		t.Errorf("ReadRaw gave %v, want ErrNegativeLength", err)
	}
	if err := r.Done(); !errors.Is(err, ErrNegativeLength) {
		t.Errorf("Done gave %v, want ErrNegativeLength", err)
	}
}
