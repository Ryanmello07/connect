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
// through all five write methods (WriteUint8, WriteUint16, WriteUint32, WriteUint64,
// WriteRaw), since each carries the identical error guard at a distinct call site.
func TestWriterErrorIsStickyAndSuppressesLaterWrites(t *testing.T) {
	w := NewWriter()
	w.WriteUint8(0x01)
	w.setErr(ErrLengthExceedsMax)
	w.setErr(ErrTruncated)
	w.WriteUint16(0xffff)
	w.WriteUint32(0xffffffff)
	w.WriteUint64(0xffffffffffffffff)
	w.WriteRaw([]byte{0xff, 0xff, 0xff})
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
