// The top level entry points every MLS structure and every record is encoded and
// decoded through, and the two interfaces every wire type in package mls
// implements.
//
// MarshalMLS returns an error and the Writer also carries a sticky one, and
// Marshal joins them. The two carry different things: the sticky error is a buffer
// failure — an over long vector, a varint out of range — and the returned error is
// a semantic refusal, which is an encoder declining to serialize a value the
// profile forbids, such as a credential type outside the v1 profile or a content
// arm that disagrees with its discriminant. This package exports no way to inject
// a refusal into the sticky error, so without the return an encoder would have to
// panic or drop it, and a dropped encoder refusal produces wrong signed bytes
// rather than a failure. Only the leaf writes stay return free, which is most of
// the call sites. UnmarshalMLS returns an error per call, because decoding is a
// branch per field and every branch matters.
//
// Unmarshal joins the same way, against Done rather than the sticky error. A
// decoder that ignores a tail accepts two encodings of one object, and MLS signs
// over serialized forms, so that is a signature bypass primitive rather than a
// leniency — and a decoder that refuses on semantic grounds partway through a
// message has left a tail behind it that the caller is entitled to hear about
// alongside the refusal. Returning early on the decoder's error would report the
// refusal and hide the tail; the join reports both, exactly as the encode half
// does.
package syntax

import "errors"

// Marshaler is the encode half of the one method set every wire type in package
// mls implements. The error is the encoder's own semantic refusal, distinct from
// the buffer failures the Writer accumulates in its sticky error.
type Marshaler interface {
	MarshalMLS(w *Writer) error
}

// Unmarshaler is the decode half. Decoding branches per field, so unlike the leaf
// writes there is no return free form of it.
type Unmarshaler interface {
	UnmarshalMLS(r *Reader) error
}

// Codec is both halves, which is what every MLS structure implements and asserts
// against with a var _ Codec line in its own file, so that a type which drifts out
// of the method set fails at build rather than at the interop gate.
type Codec interface {
	Marshaler
	Unmarshaler
}

// Marshal encodes v under the default vector length limit MaxVectorLength, which
// is correct for every structure but the ratchet tree.
func Marshal(v Marshaler) ([]byte, error) {
	return MarshalLimit(v, MaxVectorLength)
}

// MarshalLimit encodes v under a caller chosen vector length limit; the ratchet
// tree paths pass MaxRatchetTreeLength and nothing else raises the bound. Marshal
// is this with the default limit rather than a second copy of the sequence, so the
// two cannot drift apart in which errors they surface.
//
// The join is the point: a semantic refusal from the encoder and a buffer failure
// from the Writer are different failures, either one alone must fail the encode,
// and an encoder that refuses may well also have left the Writer in a state worth
// reporting. The bytes are dropped whenever either fires, so a caller cannot take
// a partial encoding by accident.
func MarshalLimit(v Marshaler, maxVectorLength int) ([]byte, error) {
	w := NewWriterLimit(maxVectorLength)
	marshalErr := v.MarshalMLS(w)
	bs, writerErr := w.Bytes()
	if err := errors.Join(marshalErr, writerErr); err != nil {
		return nil, err
	}
	return bs, nil
}

// Unmarshal decodes bs into v under the default vector length limit
// MaxVectorLength, enforcing full consumption.
func Unmarshal(bs []byte, v Unmarshaler) error {
	return UnmarshalLimit(bs, v, MaxVectorLength)
}

// UnmarshalLimit decodes bs into v under a caller chosen vector length limit; the
// ratchet tree paths — tree_sync.go, UnmarshalRatchetTree, and any GroupInfo or
// Welcome decode that may carry a tree — pass MaxRatchetTreeLength and nothing
// else raises the bound. Unmarshal is this with the default limit.
//
// The result joins the decoder's error with Done, mirroring MarshalLimit rather
// than returning early on the first of the two. The decoder's error and Done's
// answer are independent facts: a decoder can refuse a structure on semantic
// grounds with every one of its reads having succeeded, and in that case the
// bytes it never reached are still sitting there unconsumed. An early return would
// report the refusal and say nothing about the tail, which is the same asymmetry
// that would let a decoder under consume its input undetected the moment it also
// had something else to complain about. Joining costs a duplicated error in the
// case where a failed read latched and Done reports that same latched error back,
// which is the tradeoff the encode half already makes; errors.Is holds through a
// join either way.
func UnmarshalLimit(bs []byte, v Unmarshaler, maxVectorLength int) error {
	r := NewReaderLimit(bs, maxVectorLength)
	return errors.Join(v.UnmarshalMLS(r), r.Done())
}
