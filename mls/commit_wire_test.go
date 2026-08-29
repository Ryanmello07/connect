// The Commit wire codec.
//
// The presence octet is the whole of what is interesting here. RFC 9420's optional<T> has exactly
// two encodings, and a third would be a second encoding of one object -- which is the
// signature-bypass primitive, since a signature covers one serialization and a receiver that
// accepted two readings of the same bytes has two objects claiming one signature.
package mls

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

func TestCommitRoundTripWithoutPath(t *testing.T) {
	commit := Commit{
		Proposals: []ProposalOrRef{
			{Type: ProposalOrRefTypeReference, Reference: ProposalRef{0x01, 0x02}},
		},
	}
	encoded, err := syntax.Marshal(&commit)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if encoded[len(encoded)-1] != 0x00 {
		t.Fatalf("absent path encoded as %02x, want 00", encoded[len(encoded)-1])
	}

	decoded := Commit{}
	if err := syntax.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Path != nil {
		t.Fatal("path decoded as present")
	}
	if len(decoded.Proposals) != 1 || decoded.Proposals[0].Type != ProposalOrRefTypeReference {
		t.Fatalf("proposals %+v", decoded.Proposals)
	}
	reencoded, err := syntax.Marshal(&decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
	}
}

func TestCommitRoundTripEmptyProposals(t *testing.T) {
	commit := Commit{}
	encoded, err := syntax.Marshal(&commit)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded := Commit{}
	if err := syntax.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded.Proposals) != 0 || decoded.Path != nil {
		t.Fatalf("decoded %+v", decoded)
	}
	reencoded, err := syntax.Marshal(&decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
	}
}

// The present arm, which the two tests above never reach: an absent path and a present one
// differ by one octet at the front of the value, and a codec that wrote the presence octet and
// then forgot the path round trips the absent case perfectly.
func TestCommitRoundTripWithAPath(t *testing.T) {
	commit := Commit{
		Proposals: []ProposalOrRef{
			{Type: ProposalOrRefTypeReference, Reference: ProposalRef{0x01, 0x02}},
		},
		Path: &UpdatePath{LeafNode: *testLeafNodeOfSource(LeafNodeSourceCommit)},
	}
	encoded, err := syntax.Marshal(&commit)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	withoutPath := Commit{Proposals: commit.Proposals}
	absent, err := syntax.Marshal(&withoutPath)
	if err != nil {
		t.Fatalf("marshal without the path: %v", err)
	}
	if len(encoded) <= len(absent) {
		t.Fatalf("a commit carrying a path encoded to %d octets and one carrying none to %d", len(encoded), len(absent))
	}
	if encoded[len(absent)-1] != 0x01 {
		t.Fatalf("present path encoded its presence octet as %02x, want 01", encoded[len(absent)-1])
	}

	decoded := Commit{}
	if err := syntax.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Path == nil {
		t.Fatal("a commit carrying a path decoded with none")
	}
	reencoded, err := syntax.Marshal(&decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
	}
}

func TestCommitRejectsInvalidOptionalPresenceByte(t *testing.T) {
	commit := Commit{}
	valid, err := syntax.Marshal(&commit)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded := append([]byte(nil), valid...)
	encoded[len(encoded)-1] = 0x02

	decoded := Commit{}
	// the sentinel is the syntax package's: optional<T> presence is the codec's concern and
	// not framing's, so there is one place in the system that decides what optional<T> means
	if err := syntax.Unmarshal(encoded, &decoded); !errors.Is(err, syntax.ErrOptionalPresence) {
		t.Fatalf("got %v, want syntax.ErrOptionalPresence", err)
	}
}

// TestCommitReturnsThePresenceRefusalRatherThanLeaningOnTheStickyReader is the half of the
// presence refusal that going through syntax.Unmarshal cannot observe.
//
// Measured, not supposed: with the presence error swallowed -- `if err != nil { present = false }`
// where the codec returns it -- TestCommitRejectsInvalidOptionalPresenceByte above still passes,
// because ReadOptional LATCHES the failure on the Reader and syntax.Unmarshal's own r.Done()
// reports it afterwards. So that test states that the refusal reaches a caller who went through
// Unmarshal, and states nothing about the codec it is nominally about.
//
// This one calls UnmarshalMLS directly, which is how every enclosing codec in this package
// reaches it -- a Commit inside a FramedContent inside an AuthenticatedContent is decoded by
// method call and not by syntax.Unmarshal -- and there is no Done() at the end of those. A codec
// that swallowed the presence refusal there would hand its caller a commit with no path, out of
// bytes that said something else, with a nil error.
func TestCommitReturnsThePresenceRefusalRatherThanLeaningOnTheStickyReader(t *testing.T) {
	commit := Commit{}
	valid, err := syntax.Marshal(&commit)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded := append([]byte(nil), valid...)
	encoded[len(encoded)-1] = 0x02

	decoded := Commit{}
	if err := decoded.UnmarshalMLS(syntax.NewReader(encoded)); !errors.Is(err, syntax.ErrOptionalPresence) {
		t.Fatalf("the codec answered %v to a presence octet of 0x02; every enclosing codec in this package reaches it by method call and never runs a Done() that could report the latched failure instead",
			err)
	}
}
