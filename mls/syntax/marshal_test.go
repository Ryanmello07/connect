// The top level entry points. Unmarshal enforces full consumption, because a
// decoder that ignores a tail accepts two encodings of one object and MLS signs
// over serialized forms.
package syntax

import (
	"bytes"
	"errors"
	"testing"
)

type marshalProbe struct {
	Value uint16
	Body  []byte
}

var _ Codec = (*marshalProbe)(nil)

func (self *marshalProbe) MarshalMLS(w *Writer) error {
	w.WriteUint16(self.Value)
	w.WriteOpaque(self.Body)
	return nil
}

func (self *marshalProbe) UnmarshalMLS(r *Reader) error {
	value, err := r.ReadUint16()
	if err != nil {
		return err
	}
	body, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	self.Value = value
	self.Body = body
	return nil
}

func TestMarshalUnmarshalRoundTrips(t *testing.T) {
	in := marshalProbe{Value: 0xbeef, Body: []byte{0xaa, 0xbb}}
	bs, err := Marshal(&in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(bs, []byte{0xbe, 0xef, 0x02, 0xaa, 0xbb}) {
		t.Errorf("encoded %x, want beef02aabb", bs)
	}
	out := marshalProbe{}
	if err := Unmarshal(bs, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Value != in.Value || !bytes.Equal(out.Body, in.Body) {
		t.Errorf("decoded %#x %x, want %#x %x", out.Value, out.Body, in.Value, in.Body)
	}
}

func TestUnmarshalRejectsATrailingByte(t *testing.T) {
	out := marshalProbe{}
	err := Unmarshal([]byte{0xbe, 0xef, 0x02, 0xaa, 0xbb, 0x99}, &out)
	if !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("gave %v, want ErrTrailingBytes", err)
	}
}

func TestUnmarshalPropagatesADecodeError(t *testing.T) {
	out := marshalProbe{}
	if err := Unmarshal([]byte{0xbe}, &out); !errors.Is(err, ErrTruncated) {
		t.Errorf("gave %v, want ErrTruncated", err)
	}
}

// the whole reason MarshalMLS returns an error rather than routing everything into
// the sticky error: an encoder refusal that is not a buffer error — a credential type
// outside the v1 profile, a content arm that disagrees with its discriminant — must
// reach the caller, because dropping it produces wrong signed bytes rather than a
// failure
type refusingProbe struct{}

var _ Codec = (*refusingProbe)(nil)

var errProbeRefusal = errors.New("mls syntax: probe refuses to encode")

func (self *refusingProbe) MarshalMLS(w *Writer) error {
	w.WriteUint16(0xbeef)
	return errProbeRefusal
}

func (self *refusingProbe) UnmarshalMLS(r *Reader) error {
	_, err := r.ReadUint16()
	return err
}

func TestMarshalSurfacesASemanticRefusal(t *testing.T) {
	bs, err := Marshal(&refusingProbe{})
	if !errors.Is(err, errProbeRefusal) {
		t.Errorf("Marshal gave %v, want the encoder's refusal", err)
	}
	if bs != nil {
		t.Errorf("Marshal returned %x alongside a refusal, want nil", bs)
	}
	if _, err := MarshalLimit(&refusingProbe{}, MaxRatchetTreeLength); !errors.Is(err, errProbeRefusal) {
		t.Errorf("MarshalLimit gave %v, want the encoder's refusal", err)
	}
}

func TestMarshalLimitBoundsTheEncoder(t *testing.T) {
	in := marshalProbe{Value: 1, Body: bytes.Repeat([]byte{0x11}, 64)}
	if _, err := MarshalLimit(&in, 32); !errors.Is(err, ErrLengthExceedsMax) {
		t.Errorf("gave %v, want ErrLengthExceedsMax", err)
	}
	if _, err := MarshalLimit(&in, 128); err != nil {
		t.Errorf("gave %v under a sufficient limit, want nil", err)
	}
}

func TestUnmarshalLimitRaisesTheDecoderBound(t *testing.T) {
	in := marshalProbe{Value: 1, Body: bytes.Repeat([]byte{0x11}, 64)}
	bs, err := Marshal(&in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := marshalProbe{}
	if err := UnmarshalLimit(bs, &out, 32); !errors.Is(err, ErrLengthExceedsMax) {
		t.Errorf("gave %v under a low limit, want ErrLengthExceedsMax", err)
	}
	if err := UnmarshalLimit(bs, &out, MaxRatchetTreeLength); err != nil {
		t.Errorf("gave %v under the ratchet tree limit, want nil", err)
	}
}

// funcProbe is an Unmarshaler whose decode is supplied per case, so the tests below
// can pin what Unmarshal does with a decoder that consumes too little, consumes
// exactly, or refuses on grounds no read of its own reported. The encode half is
// never called and exists only so the probe is usable wherever a Codec is.
type funcProbe struct {
	decode func(r *Reader) error
}

var _ Codec = (*funcProbe)(nil)

func (self *funcProbe) MarshalMLS(w *Writer) error {
	return nil
}

func (self *funcProbe) UnmarshalMLS(r *Reader) error {
	return self.decode(r)
}

var errProbeDecodeRefusal = errors.New("mls syntax: probe refuses to decode")

// TestUnmarshalReportsATailAlongsideADecoderRefusal is the test the plan's own
// sample fails. That sample returns the decoder's error and never consults Done, so
// a decoder that refuses on semantic grounds partway through a message reports the
// refusal and hides the four bytes it never reached — and a refusal latches nothing
// on the Reader, since every read it made succeeded, so there is no second place the
// tail could surface from. Joining the two reports both, which is what the encode
// half already does with the Writer's sticky error. The refusal must still be
// reported: this asserts the join is more informative, not that it traded one report
// for another.
func TestUnmarshalReportsATailAlongsideADecoderRefusal(t *testing.T) {
	probe := funcProbe{
		decode: func(r *Reader) error {
			if _, err := r.ReadUint16(); err != nil {
				return err
			}
			return errProbeDecodeRefusal
		},
	}
	err := Unmarshal([]byte{0xbe, 0xef, 0x11, 0x22, 0x33, 0x44}, &probe)
	if !errors.Is(err, errProbeDecodeRefusal) {
		t.Errorf("gave %v, want the decoder's refusal", err)
	}
	if !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("gave %v, want the 4 unconsumed bytes reported alongside the refusal", err)
	}
}

// TestUnmarshalRejectsAnUnderConsumingDecoder covers the full consumption rule from
// the side an appended byte cannot reach. Every case here is fed input that is
// exactly the right length for what was encoded, so nothing is trailing in the
// input's own terms; what varies is how much of it the decoder reads. A decoder that
// stops early and reports success must be ErrTrailingBytes, and the exactly
// consuming case is in the same table so that "stopped early" is measured against a
// decoder that did not, rather than against an assumption.
func TestUnmarshalRejectsAnUnderConsumingDecoder(t *testing.T) {
	input := []byte{0xbe, 0xef, 0x11, 0x22}
	cases := []struct {
		consumed int
		decode   func(r *Reader) error
		want     error
	}{
		{
			consumed: 0,
			decode:   func(r *Reader) error { return nil },
			want:     ErrTrailingBytes,
		},
		{
			consumed: 2,
			decode:   func(r *Reader) error { _, err := r.ReadUint16(); return err },
			want:     ErrTrailingBytes,
		},
		{
			consumed: 3,
			decode:   func(r *Reader) error { _, err := r.ReadRaw(3); return err },
			want:     ErrTrailingBytes,
		},
		{
			consumed: 4,
			decode:   func(r *Reader) error { _, err := r.ReadUint32(); return err },
			want:     nil,
		},
	}
	for _, c := range cases {
		probe := funcProbe{decode: c.decode}
		err := Unmarshal(input, &probe)
		if c.want == nil && err != nil {
			t.Errorf("a decoder consuming all %d bytes gave %v, want nil", c.consumed, err)
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("a decoder consuming %d of %d bytes gave %v, want %v", c.consumed, len(input), err, c.want)
		}
	}
}

// TestMarshalAndUnmarshalCarryTheirLimits pins what each entry point bounds its
// buffer by. The two unlimited forms are implemented as the limit taking forms
// called with the default rather than as second copies of the sequence, so what
// keeps the default from drifting is this rather than a duplicated constant, and the
// raised bound is asserted here too so that the ratchet tree paths have the property
// they depend on pinned at the entry point they call.
func TestMarshalAndUnmarshalCarryTheirLimits(t *testing.T) {
	probe := limitReportingProbe{}
	if _, err := Marshal(&probe); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if probe.writerLimit != MaxVectorLength {
		t.Errorf("Marshal bounded the Writer at %d, want MaxVectorLength", probe.writerLimit)
	}
	if err := Unmarshal(nil, &probe); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if probe.readerLimit != MaxVectorLength {
		t.Errorf("Unmarshal bounded the Reader at %d, want MaxVectorLength", probe.readerLimit)
	}
	if _, err := MarshalLimit(&probe, MaxRatchetTreeLength); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if probe.writerLimit != MaxRatchetTreeLength {
		t.Errorf("MarshalLimit bounded the Writer at %d, want MaxRatchetTreeLength", probe.writerLimit)
	}
	if err := UnmarshalLimit(nil, &probe, MaxRatchetTreeLength); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if probe.readerLimit != MaxRatchetTreeLength {
		t.Errorf("UnmarshalLimit bounded the Reader at %d, want MaxRatchetTreeLength", probe.readerLimit)
	}
}

// limitReportingProbe records the vector length limit of whichever buffer it was
// handed, and writes and reads nothing, so the limit is all that is under test.
type limitReportingProbe struct {
	writerLimit int
	readerLimit int
}

var _ Codec = (*limitReportingProbe)(nil)

func (self *limitReportingProbe) MarshalMLS(w *Writer) error {
	self.writerLimit = w.MaxVectorLength()
	return nil
}

func (self *limitReportingProbe) UnmarshalMLS(r *Reader) error {
	self.readerLimit = r.MaxVectorLength()
	return nil
}

// TestMarshalLimitAndUnmarshalLimitRejectANegativeLimit carries the API misuse
// contract NewWriterLimit and NewReaderLimit already document up to the entry
// points, which is where every caller outside this package meets it.
func TestMarshalLimitAndUnmarshalLimitRejectANegativeLimit(t *testing.T) {
	in := marshalProbe{Value: 1, Body: []byte{0xaa}}
	if _, err := MarshalLimit(&in, -1); !errors.Is(err, ErrNegativeLength) {
		t.Errorf("MarshalLimit gave %v, want ErrNegativeLength", err)
	}
	out := marshalProbe{}
	if err := UnmarshalLimit([]byte{0xbe, 0xef, 0x01, 0xaa}, &out, -1); !errors.Is(err, ErrNegativeLength) {
		t.Errorf("UnmarshalLimit gave %v, want ErrNegativeLength", err)
	}
}
