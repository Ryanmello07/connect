// The encode half of the codec. Writer accumulates bytes and carries a sticky
// error: the first failure is retained, every write after it is a no op, and Bytes
// reports it. Encoding a value is a straight line of writes, so one check at the
// end is both sufficient and impossible to skip, because Bytes will not hand back
// the bytes without also handing back the error.
//
// Not safe for concurrent use.
package syntax

import "encoding/binary"

// Writer accumulates the TLS presentation language encoding of an MLS structure.
// Not safe for concurrent use.
type Writer struct {
	bs              []byte
	err             error
	maxVectorLength int
}

// NewWriter returns a Writer bounded by the default vector length limit
// MaxVectorLength, which is correct for every field but the ratchet tree.
func NewWriter() *Writer {
	return &Writer{
		bs:              nil,
		err:             nil,
		maxVectorLength: MaxVectorLength,
	}
}

// NewWriterLimit returns a Writer bounded by a caller chosen vector length limit;
// the ratchet tree paths pass MaxRatchetTreeLength and nothing else raises it.
func NewWriterLimit(maxVectorLength int) *Writer {
	return &Writer{
		bs:              nil,
		err:             nil,
		maxVectorLength: maxVectorLength,
	}
}

// Bytes returns the accumulated encoding, or the first error seen. The returned
// bytes are nil whenever the error is non nil, so a caller cannot take a
// truncated encoding by accident; the result is undefined if err is non-nil and
// bs was mutated after the fact, which no method in this package does.
func (self *Writer) Bytes() ([]byte, error) {
	if self.err != nil {
		return nil, self.err
	}
	return self.bs, nil
}

// Err returns the first error set on this Writer, or nil if no write has failed.
func (self *Writer) Err() error {
	return self.err
}

// Len returns the number of bytes accumulated so far. It does not reflect
// pending writes suppressed by a sticky error, since those never happened.
func (self *Writer) Len() int {
	return len(self.bs)
}

// MaxVectorLength returns the vector length limit this Writer was constructed
// with, either the package default or a caller supplied override.
func (self *Writer) MaxVectorLength() int {
	return self.maxVectorLength
}

// setErr records err as the sticky error if none has been recorded yet; first
// error wins, so the reported failure is the cause rather than a downstream
// symptom of it.
func (self *Writer) setErr(err error) {
	if self.err == nil {
		self.err = err
	}
}

// WriteUint8 appends v as a single byte. A no op once the Writer has failed.
func (self *Writer) WriteUint8(v uint8) {
	if self.err != nil {
		return
	}
	self.bs = append(self.bs, v)
}

// WriteUint16 appends v as two big endian bytes. A no op once the Writer has failed.
func (self *Writer) WriteUint16(v uint16) {
	if self.err != nil {
		return
	}
	self.bs = binary.BigEndian.AppendUint16(self.bs, v)
}

// WriteUint32 appends v as four big endian bytes. A no op once the Writer has failed.
func (self *Writer) WriteUint32(v uint32) {
	if self.err != nil {
		return
	}
	self.bs = binary.BigEndian.AppendUint32(self.bs, v)
}

// WriteUint64 appends v as eight big endian bytes. A no op once the Writer has failed.
func (self *Writer) WriteUint64(v uint64) {
	if self.err != nil {
		return
	}
	self.bs = binary.BigEndian.AppendUint64(self.bs, v)
}

// WriteRaw appends bs verbatim with no length prefix: opaque x[N], for a field
// whose length the surrounding structure already fixes. A nil or empty bs writes
// nothing. A no op once the Writer has failed.
func (self *Writer) WriteRaw(bs []byte) {
	if self.err != nil {
		return
	}
	self.bs = append(self.bs, bs...)
}
