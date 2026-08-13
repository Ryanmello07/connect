// The decode half of the codec, and the mirror of Writer in encode.go. Reader is a
// cursor over a byte slice: every read is bounds checked against the bytes that
// remain before it advances the cursor, so a failed read leaves the cursor exactly
// where it was. The first failure is sticky: it latches into the Reader, so every
// later read and Done report that same error instead of running their own check
// against bytes the failed read never validated. Without this, a caller that
// ignores one failed read could have a later, smaller read silently succeed
// against the same untouched bytes and reinterpret them as a different field —
// a structurally valid decode of the wrong fields, with no error to catch it. So
// the first error reported is always the cause rather than a downstream symptom
// of it, matching the sticky error Writer carries in encode.go, for the same
// reason: a caller that does not check every return should not get a silently
// wrong decode. This file carries the cursor and the fixed-width portion of the
// contract — ReadUint8/16/32/64, ReadRaw and the full consumption check Done.
// Tasks 6 and 8-11 add the variable length reads (ReadVarint, ReadOpaque,
// ReadOpaqueLP, ReadSub, ReadSubLP, ReadOptional) to this same file; those are
// where a declared length gets checked against the configured maximum and the
// bytes that remain before anything is allocated, so a hostile length prefix can
// never size an allocation.
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
// that remain before it advances the cursor, so a failed read never moves it, and
// the first failure sticks: once any read fails, every subsequent read and Done
// report that same error instead of re-checking bytes the failed read never
// validated, matching Writer's sticky error in encode.go. Not safe for
// concurrent use.
type Reader struct {
	bs              []byte
	pos             int
	maxVectorLength int
	// err is the sticky error. It starts out set only when NewReaderLimit is
	// given a negative limit — the same validate-at-construction precedent
	// NewWriterLimit follows in encode.go — and from then on every read method
	// that fails also calls setErr, first error wins. Checked first by every
	// method that returns an error, so a caller who ignores one failed read
	// cannot have a later read silently reinterpret the same, still-unconsumed
	// bytes as a different, smaller field and succeed.
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

// setErr records err as the sticky error if none has been recorded yet; first
// error wins, so a later, unrelated failure never overwrites the cause — the
// same first-error-wins rule Writer.setErr enforces in encode.go.
func (self *Reader) setErr(err error) {
	if self.err == nil {
		self.err = err
	}
}

// Done returns the sticky error if one was set — either the construction time
// misuse or a prior read's latched failure — otherwise ErrTrailingBytes if bytes
// remain unconsumed, otherwise nil. This is the full consumption rule: a decoder
// that ignores a tail accepts two encodings of one object, and MLS signs over
// serialized forms.
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
// not advance on failure, and the failure latches: every later read and Done on
// this Reader report the same error instead of running their own check.
func (self *Reader) ReadUint8() (uint8, error) {
	if self.err != nil {
		return 0, self.err
	}
	if self.Remaining() < 1 {
		self.setErr(ErrTruncated)
		return 0, self.err
	}
	v := self.bs[self.pos]
	self.pos += 1
	return v, nil
}

// ReadUint16 reads two bytes, most significant byte first. Reports ErrTruncated
// if fewer than two remain; the cursor does not advance on failure, and the
// failure latches: every later read and Done on this Reader report the same
// error instead of running their own check.
func (self *Reader) ReadUint16() (uint16, error) {
	if self.err != nil {
		return 0, self.err
	}
	if self.Remaining() < 2 {
		self.setErr(ErrTruncated)
		return 0, self.err
	}
	v := binary.BigEndian.Uint16(self.bs[self.pos:])
	self.pos += 2
	return v, nil
}

// ReadUint32 reads four bytes, most significant byte first. Reports ErrTruncated
// if fewer than four remain; the cursor does not advance on failure, and the
// failure latches: every later read and Done on this Reader report the same
// error instead of running their own check.
func (self *Reader) ReadUint32() (uint32, error) {
	if self.err != nil {
		return 0, self.err
	}
	if self.Remaining() < 4 {
		self.setErr(ErrTruncated)
		return 0, self.err
	}
	v := binary.BigEndian.Uint32(self.bs[self.pos:])
	self.pos += 4
	return v, nil
}

// ReadUint64 reads eight bytes, most significant byte first. Reports
// ErrTruncated if fewer than eight remain; the cursor does not advance on
// failure, and the failure latches: every later read and Done on this Reader
// report the same error instead of running their own check.
func (self *Reader) ReadUint64() (uint64, error) {
	if self.err != nil {
		return 0, self.err
	}
	if self.Remaining() < 8 {
		self.setErr(ErrTruncated)
		return 0, self.err
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
// on failure, and the failure latches: every later read and Done on this Reader
// report the same error instead of running their own check.
func (self *Reader) ReadRaw(n int) ([]byte, error) {
	if self.err != nil {
		return nil, self.err
	}
	if n < 0 {
		self.setErr(ErrNegativeLength)
		return nil, self.err
	}
	if n > self.Remaining() {
		self.setErr(ErrTruncated)
		return nil, self.err
	}
	out := make([]byte, n)
	copy(out, self.bs[self.pos:self.pos+n])
	self.pos += n
	return out, nil
}

// validateLength checks a declared length before the caller may allocate
// anything sized by it: first against self.err, so a Reader that already carries
// a latched failure can never validate n and hand back a clean result, which
// would revive reads the sticky contract says must stay dead — matching every
// other error-returning method in this file. Then against this Reader's
// configured maximum, reporting
// ErrLengthExceedsMax, then — only once that check has passed — against the
// bytes actually remaining in the input, reporting ErrLengthExceedsInput. The two
// failures are kept distinct because downstream callers need to tell "this field
// is simply too large" apart from "this input was truncated or lied about its
// length." n is a uint32 straight from ReadVarint and both comparisons widen to
// int64 before comparing, so a length near the uint32 range on a platform where
// int is 32 bits can never wrap around into looking small and passing either
// check; only once both checks pass is n narrowed to int for the caller to size a
// make with. Named for what it does, not for a cursor motion: it validates and
// deliberately does not touch the cursor, leaving that to the caller.
func (self *Reader) validateLength(n uint32) (int, error) {
	if self.err != nil {
		return 0, self.err
	}
	if int64(n) > int64(self.maxVectorLength) {
		self.setErr(ErrLengthExceedsMax)
		return 0, self.err
	}
	if int64(n) > int64(self.Remaining()) {
		self.setErr(ErrLengthExceedsInput)
		return 0, self.err
	}
	return int(n), nil
}

// ReadOpaque decodes opaque x<V>: a varint length prefix read by ReadVarint,
// then that many bytes. The declared length is validated by validateLength —
// against the configured maximum and then against the bytes actually remaining —
// before any allocation, so a hostile length prefix can never size a make; the
// two rejections surface as the distinct sentinels ErrLengthExceedsMax and
// ErrLengthExceedsInput. The result is always a copy, never a view into the
// input, matching ReadRaw, and is never nil even for a zero length value, so an
// empty opaque field and an absent one stay distinguishable in Go despite
// encoding identically on the wire. On any failure the cursor is restored to
// where it stood before this call — not left partway past a validly decoded
// varint whose length then failed — and the failure latches: every later read
// and Done on this Reader report the same error.
func (self *Reader) ReadOpaque() ([]byte, error) {
	if self.err != nil {
		return nil, self.err
	}
	mark := self.pos
	n, err := self.ReadVarint()
	if err != nil {
		return nil, err
	}
	length, err := self.validateLength(n)
	if err != nil {
		self.pos = mark
		return nil, err
	}
	out := make([]byte, length)
	copy(out, self.bs[self.pos:self.pos+length])
	self.pos += length
	return out, nil
}
