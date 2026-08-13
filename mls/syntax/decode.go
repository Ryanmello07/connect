// The decode half of the codec, and the mirror of Writer in encode.go. Reader is a
// cursor over a byte slice: every read is bounds checked against the bytes that
// remain before it advances the cursor, so a failed read leaves the cursor exactly
// where it was and the first error reported is always the cause rather than a
// downstream symptom of it. This file carries the cursor and the fixed-width
// portion of the contract — ReadUint8/16/32/64, ReadRaw and the full consumption
// check Done. Tasks 6 and 8-11 add the variable length reads (ReadVarint,
// ReadOpaque, ReadOpaqueLP, ReadSub, ReadSubLP, ReadOptional) to this same file;
// those are where a declared length gets checked against the configured maximum
// and the bytes that remain before anything is allocated, so a hostile length
// prefix can never size an allocation.
//
// ReadRaw's result is a copy, never a view into the input: MLS verifies a
// signature over serialized bytes and then uses the decoded fields, so a field
// that aliases a buffer someone else may reuse is a correctness hazard as well as
// a way to pin a large buffer behind a small field.
//
// Not safe for concurrent use.
package syntax

import "encoding/binary"

// Reader is a bounds-checked cursor over a byte slice. Every read checks the bytes
// that remain before it advances the cursor, so a failed read never moves it.
// Not safe for concurrent use.
type Reader struct {
	bs              []byte
	pos             int
	maxVectorLength int
	// err is the sticky construction time error. It is set only by NewReaderLimit
	// when given a negative limit, and it is checked first by every method that
	// returns an error, so that misuse is reported on every subsequent call
	// instead of being deferred to whatever bounds check would otherwise have
	// run first — the same validate-at-construction precedent NewWriterLimit
	// follows in encode.go.
	err error
}

// NewReader returns a Reader over bs bounded by the default vector length limit
// MaxVectorLength, which is correct for every field but the ratchet tree.
func NewReader(bs []byte) *Reader {
	return &Reader{
		bs:              bs,
		maxVectorLength: MaxVectorLength,
	}
}

// NewReaderLimit returns a Reader over bs bounded by a caller chosen vector length
// limit; the ratchet tree paths pass MaxRatchetTreeLength and nothing else raises
// it. Zero is a legitimate limit: a Reader that accepts no variable length
// content. A negative limit is the API misuse ErrNegativeLength documents: the
// returned Reader carries ErrNegativeLength as its sticky error from
// construction, so every read on it reports that error immediately instead of
// running its ordinary bounds check.
func NewReaderLimit(bs []byte, maxVectorLength int) *Reader {
	r := &Reader{
		bs:              bs,
		maxVectorLength: maxVectorLength,
	}
	if maxVectorLength < 0 {
		r.err = ErrNegativeLength
	}
	return r
}

// Offset returns the current cursor position: the number of bytes consumed so
// far. Like Writer.Len, it does not reflect the sticky construction time error.
func (self *Reader) Offset() int {
	return self.pos
}

// Remaining returns the number of bytes not yet consumed.
func (self *Reader) Remaining() int {
	return len(self.bs) - self.pos
}

// Empty reports whether every byte of the input has been consumed.
func (self *Reader) Empty() bool {
	return self.pos >= len(self.bs)
}

// MaxVectorLength returns the vector length limit this Reader was constructed
// with, either the package default or a caller supplied override.
func (self *Reader) MaxVectorLength() int {
	return self.maxVectorLength
}

// Done returns the sticky construction time error if one was set; otherwise
// ErrTrailingBytes if bytes remain unconsumed; otherwise nil. This is the full
// consumption rule: a decoder that ignores a tail accepts two encodings of one
// object, and MLS signs over serialized forms.
func (self *Reader) Done() error {
	if self.err != nil {
		return self.err
	}
	if !self.Empty() {
		return ErrTrailingBytes
	}
	return nil
}

// ReadUint8 reads one byte. Reports ErrTruncated if none remain; the cursor does
// not advance on failure.
func (self *Reader) ReadUint8() (uint8, error) {
	if self.err != nil {
		return 0, self.err
	}
	if self.Remaining() < 1 {
		return 0, ErrTruncated
	}
	v := self.bs[self.pos]
	self.pos += 1
	return v, nil
}

// ReadUint16 reads two bytes, most significant byte first. Reports ErrTruncated
// if fewer than two remain; the cursor does not advance on failure.
func (self *Reader) ReadUint16() (uint16, error) {
	if self.err != nil {
		return 0, self.err
	}
	if self.Remaining() < 2 {
		return 0, ErrTruncated
	}
	v := binary.BigEndian.Uint16(self.bs[self.pos:])
	self.pos += 2
	return v, nil
}

// ReadUint32 reads four bytes, most significant byte first. Reports ErrTruncated
// if fewer than four remain; the cursor does not advance on failure.
func (self *Reader) ReadUint32() (uint32, error) {
	if self.err != nil {
		return 0, self.err
	}
	if self.Remaining() < 4 {
		return 0, ErrTruncated
	}
	v := binary.BigEndian.Uint32(self.bs[self.pos:])
	self.pos += 4
	return v, nil
}

// ReadUint64 reads eight bytes, most significant byte first. Reports
// ErrTruncated if fewer than eight remain; the cursor does not advance on
// failure.
func (self *Reader) ReadUint64() (uint64, error) {
	if self.err != nil {
		return 0, self.err
	}
	if self.Remaining() < 8 {
		return 0, ErrTruncated
	}
	v := binary.BigEndian.Uint64(self.bs[self.pos:])
	self.pos += 8
	return v, nil
}

// ReadRaw reads the next n bytes verbatim: opaque x[N], for a field whose length
// the surrounding structure already fixes. The result is always a copy, never a
// view into the input, so a decoded field cannot be mutated through the buffer
// it came from and cannot pin it. Reports ErrNegativeLength if n is negative;
// reports ErrTruncated if fewer than n bytes remain. The cursor does not advance
// on failure.
func (self *Reader) ReadRaw(n int) ([]byte, error) {
	if self.err != nil {
		return nil, self.err
	}
	if n < 0 {
		return nil, ErrNegativeLength
	}
	if n > self.Remaining() {
		return nil, ErrTruncated
	}
	out := make([]byte, n)
	copy(out, self.bs[self.pos:self.pos+n])
	self.pos += n
	return out, nil
}
