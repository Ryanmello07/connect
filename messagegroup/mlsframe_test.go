// MASTER section 8.4 held as cases: the forgery it closes, the two refusals it owes, the size it
// costs, and the one thing it stops working.
//
// THE PROPERTY THIS FILE EXISTS FOR IS ONE SENTENCE: a member must not be able to forge a message
// from another member. Before 2026-09-15 it could -- RecordKeyZero(class_key, leaf) needs only the
// class key every member holds and a leaf number, and messagegroup/seal.go contained no signature
// at all -- and a case in m1w1repairs_test.go asserted that as a standing property of this
// package. That case is not deleted here. It is NARROWED, to
// TestAnyMemberCanStillSquatAnotherLeafsStreamIndex, which holds the half of the finding that
// survives: a denial rather than a forgery, ledger open item 205.
//
// EVERY NUMBER IN THIS FILE IS MEASURED BY A CASE IN THIS FILE and none is transcribed from the
// ruling. The ladder below re-derives its own column by calling Protect and walking; if the ruling
// and this tree ever disagree, the disagreement is a failure here rather than a comment somebody
// reads past.
package messagegroup

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/mls"
	"github.com/urnetwork/connect/mls/syntax"
)

// ---------------------------------------------------------------------------
// the property: one member cannot forge a message from another
// ---------------------------------------------------------------------------

// The forgery, written from the attacker's side and refused at a named error.
//
// THE THREE ROLES ARE THREE DIFFERENT DEVICES' WORTH OF STATE and they are not interchangeable:
//
//	A  the founder, whose messages are being forged. It is also the OPENER here, because the
//	   opener must not be the forger -- a forger opening its own frame meets MG-4's self-Unprotect
//	   refusal first and would observe the wrong sentence entirely.
//	B  the joiner, the FORGER. It is a full member holding everything a member holds: the same
//	   storage root, the same three class keys, the same group_handle_key, the same write key. It
//	   holds one thing A does not, which is B's own MLS signing key, and one thing it can never
//	   hold, which is A's.
//
// WHAT B DOES is every step of the seal path, by hand, out of exported symbols: derive A's record
// key from the shared DURABLE class key and A's LEAF NUMBER, compute A's sender_handle from the
// shared group_handle_key and the same leaf number, seal a body under it, hash it, seal a head,
// and mac the record under the group's write key. Every one of those inputs is group-shared by
// construction, which is why no amount of care in the record layer could ever have refused this.
//
// AND B PUTS A REAL MLS FRAME IN IT, which is the strongest form of the attack rather than the
// easiest. A body of arbitrary octets is refused by mls before either of MASTER section 8.4.3's
// refusals is reached, and a case that only did that would leave R1 untested: it would be
// asserting that a malformed body is malformed. So B calls its OWN Protect, with the aad this
// record's position produces, and gets a frame that verifies perfectly -- at leaf B.
//
// THE REFUSAL IS R1 AND ITS ERROR IS NAMED. If the sender binding is ever removed, this case goes
// red with the forged record opening as A's, which is the whole point of writing it.
func TestOneMemberCannotForgeAMessageFromAnother(t *testing.T) {
	pair := newTestPair(t, "one-member-cannot-forge")
	forger := pair.chain.joined
	forgerSession := pair.opener
	victimLeaf := pair.senderLeaf
	opener := pair.sender

	// A tracks its OWN ladder, which is what makes a record attributed to A something A's
	// opener will look at at all. It is also what MG-4 makes impossible for a genuine record,
	// and the control below is at a leaf A can receive from, precisely so this case is not
	// resting on that.
	if err := opener.TrackSender(victimLeaf, message.RetentionDurable, 0, 0, 0); err != nil {
		t.Fatalf("A tracks its own ladder: %v", err)
	}
	if err := opener.TrackSender(pair.openerLeaf, message.RetentionDurable, 0, 0, 0); err != nil {
		t.Fatalf("A tracks B's ladder: %v", err)
	}

	// THE CONTROL FIRST, so that the refusal below is a refusal of the forgery and not of the
	// fixture. Same opener, same class, same ladder machinery, a real signature -- and the one
	// thing that differs is that the record's sender_handle is the handle of the leaf that
	// signed it.
	honest, err := pair.opener.SealRecord(message.RetentionDurable, 0, false,
		[]byte("head B wrote"), []byte("body B wrote"), 0, nil)
	if err != nil {
		t.Fatalf("B's own SealRecord: %v", err)
	}
	gotHead, gotBody, err := opener.OpenRecord(honest)
	if err != nil {
		t.Fatalf("A could not open a record B really wrote, so nothing below is about forgery: %v", err)
	}
	if !bytes.Equal(gotHead, []byte("head B wrote")) || !bytes.Equal(gotBody, []byte("body B wrote")) {
		t.Fatalf("the control record opened to %q/%q", gotHead, gotBody)
	}

	// THE FORGERY. B protects under its own credential, with the aad the record it is about to
	// build produces, and then envelopes it at A's handle on A's ladder.
	aad, err := aadMls(forgeBodyBinding(forgerSession, victimLeaf, 0))
	if err != nil {
		t.Fatalf("aadMls over the forged position: %v", err)
	}
	inner, err := forger.Protect(aad[:], []byte("Alice never wrote this"))
	if err != nil {
		t.Fatalf("B's Protect: %v", err)
	}
	forged := repairForgeRecord(t, forgerSession, victimLeaf, 0,
		[]byte("a head attributed to A"), inner)
	if forged.Header.SenderHandle != SenderHandle(forgerSession.groupHandleKey, victimLeaf) {
		t.Fatal("the forged record does not carry A's sender_handle, so it is not the record this case is about")
	}

	headPlain, bodyPlain, err := opener.OpenRecord(forged)
	if !errors.Is(err, ErrRecordSenderBinding) {
		t.Errorf("a record sealed by B, attributed to A and carrying a frame B signed opened with %v; want ErrRecordSenderBinding. If it opened, one member can forge a message from another and MASTER section 8.4 is not wired",
			err)
	}
	if headPlain != nil || bodyPlain != nil {
		t.Errorf("the refusal returned %d octets of head and %d of body beside the error",
			len(headPlain), len(bodyPlain))
	}
	t.Logf("B, a full member holding every group-shared secret, sealed a record at A's handle on A's ladder with a frame B really signed, and A refused it: %v", err)

	// AND THE CRUDE FORM, which is the same attack without the frame: the octets a forger wrote
	// before this ruling existed. It is refused one step earlier, by mls, and the error names
	// that rather than naming the sender binding.
	crude := repairForgeRecord(t, forgerSession, victimLeaf, 1,
		[]byte("a head attributed to A"), []byte("Alice never wrote this either"))
	if _, _, err := opener.OpenRecord(crude); !errors.Is(err, ErrRecordInnerFrame) {
		t.Errorf("a record whose body is not an MLS frame at all opened with %v, want ErrRecordInnerFrame", err)
	}
}

// R2's own case: a frame its signer really signed, moved to a position it was not signed for.
//
// WHY IT IS A SEPARATE CASE FROM THE ONE ABOVE. R1 and R2 do not imply each other, and a suite
// that held only the forgery above would go green with R2 deleted. Here the signature is genuine,
// the leaf is genuine and the sender_handle is the signer's own -- so R1 passes, and the only
// thing wrong with the record is WHERE it is. That is MASTER section 8.4.2's re-enveloping: a
// replay into a later conversational position, indistinguishable from the sender saying it again.
//
// WHAT IS EXERCISED HERE IS THE POSITION AND NOT THE CLASS, said rather than implied. The ruling
// argues the class arm at length -- a DURABLE message dropped into EPH(1) self-destructs within
// the hour, an EPH one promoted to PERMANENT never does -- and that arm is the SAME comparison,
// because retention_class and eph_window are inside AAD_body and AAD_body is inside the digest.
// It is not separately driven here: a class move needs a second class key's ladder at both ends,
// which is a fixture and not a property, and
// TestEveryFieldOfARecordIsAuthenticatedByTheOpen already moves every header field of a record and
// requires none of them to open.
func TestASignedFrameCannotBeReEnvelopedIntoAnotherPosition(t *testing.T) {
	pair := newTestPair(t, "re-enveloping")
	forger := pair.chain.joined
	forgerSession := pair.opener
	opener := pair.sender
	if err := opener.TrackSender(pair.openerLeaf, message.RetentionDurable, 0, 0, 0); err != nil {
		t.Fatalf("A tracks B's durable ladder: %v", err)
	}

	// the frame B signs for its own handle at index 0, which is where it belongs.
	aad, err := aadMls(forgeBodyBinding(forgerSession, pair.openerLeaf, 0))
	if err != nil {
		t.Fatalf("aadMls: %v", err)
	}
	inner, err := forger.Protect(aad[:], []byte("a message B really wrote"))
	if err != nil {
		t.Fatalf("B's Protect: %v", err)
	}

	// THE CONTROL: at the position it was signed for, the same frame opens.
	atHome := repairForgeRecord(t, forgerSession, pair.openerLeaf, 0, []byte("head"), inner)
	_, gotBody, err := opener.OpenRecord(atHome)
	if err != nil {
		t.Fatalf("a frame at the position it was signed for did not open, so nothing below is about the position: %v", err)
	}
	if !bytes.Equal(gotBody, []byte("a message B really wrote")) {
		t.Fatalf("the control opened to %q", gotBody)
	}

	// MOVED ONE POSITION ALONG. Everything about the record is well formed: B's own handle, B's
	// own ladder, B's own signature, a mac under the group's write key. The frame names index 0
	// and the record is at index 1.
	moved, err := forger.Protect(aad[:], []byte("a message B really wrote"))
	if err != nil {
		t.Fatalf("B's second Protect: %v", err)
	}
	replayed := repairForgeRecord(t, forgerSession, pair.openerLeaf, 1, []byte("head"), moved)
	if _, _, err := opener.OpenRecord(replayed); !errors.Is(err, ErrRecordPositionBinding) {
		t.Errorf("a frame signed for stream_index 0 and sealed at stream_index 1 opened with %v; want ErrRecordPositionBinding. Without it, any member can replay a message into a later conversational position",
			err)
	}
}

// A REFUSED RECORD MOVES NO RECEIVER RATCHET, so the ruling does not turn a forgery it defeats
// into a denial it causes.
//
// THERE ARE TWO RECEIVER RATCHETS AND THIS CASE HOLDS BOTH, which is the repair. It used to hold
// one. Its first half drives a forged body that is not an MLS frame at all, so the refusal is taken
// by mls's parser before any key is reached, and what is observed is where the refusal sits
// relative to receivers.Commit -- this package's own ladder over stream_index. That is real and it
// is HALF the property the name states. The other half is the MLS ratchet INSIDE the frame, keyed
// on the sender's leaf and a generation, and a body that never parses can no more reach it than it
// can reach the signature. Measured, on the shape that reaches it: before this repair, a record
// carrying a genuine frame moved to the wrong position was refused at R2 -- correctly -- AFTER mls
// had opened the frame and erased the generation it came at, and the true sender's message at that
// generation then never opened again at that receiver, ever. One ordinary record per message an
// attacker wanted deleted.
//
// So half one asks "was the refusal taken before receivers.Commit" and half two asks "was it taken
// before the MLS erase", and the two are reached by different inputs: half one needs a body mls
// refuses, half two needs a body mls ACCEPTS and this package refuses. A case that drove only the
// first reports a property it has only half looked at, which is worse than no case at all, because
// the name is read as coverage.
//
// THE ORDERING IS THE DIFFERENCE between "this record is refused" and "this record is refused AND
// the true sender's own next write is refused behind it" -- a forger who cannot write as Alice can
// still put an envelope at Alice's next index, or lift Alice's own frame into a position it was not
// signed for, and an opener that moved either ladder before refusing would walk past the rung
// Alice's real record needs.
func TestARecordRefusedAtTheInnerFrameMovesNoReceiverRatchet(t *testing.T) {
	pair := newTestPair(t, "refusal-moves-nothing")
	pair.trackDurable(t)

	// ------------------------------------------------------------------
	// HALF ONE: this package's ladder over stream_index.
	// ------------------------------------------------------------------

	// the index A's next record will take, reserved by nobody yet. It is read off a record the
	// sender seals and throws away rather than written down, so a reserver that started
	// somewhere else moves this case with it.
	probe, err := pair.sender.SealRecord(message.RetentionDurable, 0, false, []byte("head"), []byte("probe"), 0, nil)
	if err != nil {
		t.Fatalf("SealRecord to read the ladder position: %v", err)
	}
	next := probe.Header.StreamIndex + 1

	forged := repairForgeRecord(t, pair.opener, pair.senderLeaf, next,
		[]byte("a head at the sender's next index"), []byte("octets that are not an MLS frame"))
	if _, _, err := pair.opener.OpenRecord(forged); !errors.Is(err, ErrRecordInnerFrame) {
		t.Fatalf("the squatted record answered %v, want ErrRecordInnerFrame; nothing below is about the ordering", err)
	}

	// and now the TRUE sender writes at that index. It must open: the refusal above authenticated
	// nothing, so it must have moved nothing.
	if _, _, err := pair.opener.OpenRecord(probe); err != nil {
		t.Fatalf("the sender's earlier record no longer opens: %v", err)
	}
	honest, err := pair.sender.SealRecord(message.RetentionDurable, 0, false, []byte("head"), []byte("the real one"), 0, nil)
	if err != nil {
		t.Fatalf("the sender's SealRecord: %v", err)
	}
	if honest.Header.StreamIndex != next {
		t.Fatalf("the sender's next record is at stream_index %d and this case squatted %d",
			honest.Header.StreamIndex, next)
	}
	_, gotBody, err := pair.opener.OpenRecord(honest)
	if err != nil {
		t.Fatalf("the true sender's record at stream_index %d no longer opens after a record at that index was refused: %v. The refusals of MASTER section 8.4.3 must be taken BEFORE the receiver ratchet commits, or every refused envelope denies the sender its own next write",
			next, err)
	}
	if !bytes.Equal(gotBody, []byte("the real one")) {
		t.Errorf("the true sender's record opened to %q", gotBody)
	}

	// ------------------------------------------------------------------
	// HALF TWO: the MLS ratchet inside the frame, which the half above cannot reach.
	// ------------------------------------------------------------------
	//
	// Both of MASTER section 8.4.3's refusals are driven, because "a record that is refused" is
	// the whole class and a rule held over one member of it is a rule held over one member of it.
	// Each row takes a record the sender REALLY sealed, lifts its frame out -- which any member
	// can do, the record key is RecordKeyZero(class_key, leaf) and the class key is group shared --
	// and re-envelopes that same frame into a record the opener must refuse. The frame is genuine,
	// so mls opens it, authenticates it and would erase its generation; only this package knows it
	// is in the wrong place. Then the sender's OWN record, the one the frame was lifted from, is
	// opened. It must still open.
	rows := []struct {
		what     string
		leafOf   func() uint32
		index    func(uint64) uint64
		sentinel error
	}{
		{
			what:     "R2, the same frame re-enveloped at another stream_index",
			leafOf:   func() uint32 { return pair.senderLeaf },
			index:    func(at uint64) uint64 { return at + 4 },
			sentinel: ErrRecordPositionBinding,
		},
		{
			what:     "R1, the same frame re-enveloped under another member's sender_handle",
			leafOf:   func() uint32 { return pair.openerLeaf },
			index:    func(at uint64) uint64 { return at },
			sentinel: ErrRecordSenderBinding,
		},
	}
	for _, row := range rows {
		genuine, err := pair.sender.SealRecord(message.RetentionDurable, 0, false,
			[]byte("head"), []byte("a message the sender really wrote"), 0, nil)
		if err != nil {
			t.Fatalf("%s: the sender's SealRecord: %v", row.what, err)
		}
		lifted := repairLiftFrame(t, pair.opener, pair.senderLeaf, genuine)
		leaf := row.leafOf()
		if leaf == pair.openerLeaf {
			if err := pair.opener.TrackSender(leaf, message.RetentionDurable, 0, 0, 0); err != nil {
				t.Fatalf("%s: tracking the forger's own ladder: %v", row.what, err)
			}
		}
		moved := repairForgeRecord(t, pair.opener, leaf, row.index(genuine.Header.StreamIndex),
			[]byte("a head somebody else wrote"), lifted)
		if _, _, err := pair.opener.OpenRecord(moved); !errors.Is(err, row.sentinel) {
			t.Fatalf("%s: the re-enveloped record answered %v, want %v; nothing below is about the ordering",
				row.what, err, row.sentinel)
		}
		// THE STAKE. The frame above was the sender's own, at a generation of the sender's own
		// MLS ratchet. If the refusal was taken after mls opened it, that generation is erased
		// at this receiver and the sender's genuine record is unopenable for the rest of time.
		_, gotBody, err := pair.opener.OpenRecord(genuine)
		if err != nil {
			t.Fatalf("%s: the sender's OWN record no longer opens after the refusal above: %v. MASTER section 8.4.3's refusals must be taken BEFORE mls consumes the generation, or any member can permanently delete any other member's message with one ordinary record",
				row.what, err)
		}
		if !bytes.Equal(gotBody, []byte("a message the sender really wrote")) {
			t.Errorf("%s: the sender's own record opened to %q", row.what, gotBody)
		}
	}
}

// ---------------------------------------------------------------------------
// what stops working, and it is not a cost of the AAD
// ---------------------------------------------------------------------------

// MG-4's reproduction: a session cannot open its own application record, and that is MLS rather
// than this package.
//
// Protect consumes a generation of THIS leaf's sending ratchet, and RFC 9420 section 9's secret
// tree gives a member no RECEIVING ratchet for its own leaf, because a member never receives its
// own messages. Spec A section 5.2's A-27 paragraph says the ruling "does not make a working call
// stop working"; it does, and the sentence that stands here is the measurement rather than the
// claim.
//
// THE CONTROL IS THE SAME SESSION SEALING A COMMIT RECORD, which MASTER section 8.4.1's first row
// leaves alone: it carries no application frame, so the record layer opens it exactly as it always
// did. That is what makes this case a statement about the FRAME and not about a record layer that
// has stopped working. It is asked for through OpenCeremonyRecord, which is where that arm's
// records go after the second pass -- the door changed, the opening did not, and the control is
// still the same session getting its own octets back.
func TestASessionCannotOpenItsOwnApplicationRecordAndThatIsMls(t *testing.T) {
	fixture := newTestSession(t, "own-application-record")
	fixture.trackOwn(t)

	application, err := fixture.session.SealRecord(message.RetentionDurable, 0, false,
		[]byte("head"), []byte("a message this device wrote"), 0, nil)
	if err != nil {
		t.Fatalf("SealRecord: %v", err)
	}
	if _, _, err := fixture.session.OpenRecord(application); !errors.Is(err, ErrRecordInnerFrame) {
		t.Errorf("a session opened a record it sealed itself and answered %v; MASTER section 8.4 makes that body an MLS frame this leaf has no receiving ratchet for, so the refusal is ErrRecordInnerFrame and open item MG-4 is what is unruled about it",
			err)
	}

	// the control: is_commit == 1, MASTER section 8.4.1 row 1, no application frame.
	commit, err := fixture.session.SealRecord(message.RetentionDurable, 0, true,
		[]byte("head"), []byte("the octets a commit record carries"), 0, nil)
	if err != nil {
		t.Fatalf("SealRecord of a commit record: %v", err)
	}
	gotHead, gotBody, err := fixture.session.OpenCeremonyRecord(commit)
	if err != nil {
		t.Fatalf("a commit record carries no application frame and must open exactly as it always did: %v", err)
	}
	// AND THE ARM SPLIT, from both sides: the message door refuses it, and the ceremony door
	// refuses the application record above. Without the pair, one door that quietly served both
	// arms would satisfy everything else in this case.
	if _, _, err := fixture.session.OpenRecord(commit); !errors.Is(err, ErrRecordNotAnApplicationRecord) {
		t.Errorf("the message door opened a commit record with %v, want ErrRecordNotAnApplicationRecord", err)
	}
	if _, _, err := fixture.session.OpenCeremonyRecord(application); !errors.Is(err, ErrRecordNotAnApplicationRecord) {
		t.Errorf("the ceremony door opened an application record with %v, want ErrRecordNotAnApplicationRecord", err)
	}
	if !bytes.Equal(gotHead, []byte("head")) || !bytes.Equal(gotBody, []byte("the octets a commit record carries")) {
		t.Errorf("the commit record opened to %q/%q", gotHead, gotBody)
	}
}

// The predicate MASTER section 8.4.1 states as a table, held as the table.
//
// It is derived from two values the sealer already holds and never from a parameter, so this case
// walks the three rows rather than the one arm a round trip happens to take. The attachment arm is
// asked through the ENCODER's answer, which is what the production predicate reads: connect/message
// collapses a nil attachment and an explicit AttachmentNone to no bytes at all, so "the attachment
// is NONE" and "the encoding is empty" are one sentence on both sides of the wire.
func TestWhichRecordsCarryAnInnerFrameIsMasterSection841sTable(t *testing.T) {
	wrap, err := message.EncodeServerAttachment(&message.ServerAttachment{
		Kind: message.AttachmentWrap,
		Wrap: &message.WrapTag{WrapTargetHandle: make([]byte, 16), Epoch: 1},
	})
	if err != nil {
		t.Fatalf("encode a wrap attachment: %v", err)
	}
	if len(wrap) == 0 {
		t.Fatal("a wrap attachment encodes to no bytes, so the third row of the table is unreachable here")
	}
	none, err := message.EncodeServerAttachment(nil)
	if err != nil {
		t.Fatalf("encode no attachment: %v", err)
	}
	explicit, err := message.EncodeServerAttachment(&message.ServerAttachment{Kind: message.AttachmentNone})
	if err != nil {
		t.Fatalf("encode an explicit AttachmentNone: %v", err)
	}
	for _, row := range []struct {
		name       string
		isCommit   bool
		attachment []byte
		want       bool
	}{
		{"a commit record", true, none, false},
		{"a commit record carrying an attachment", true, wrap, false},
		{"an application record", false, none, true},
		{"an application record whose attachment is an explicit NONE", false, explicit, true},
		{"a device wrap", false, wrap, false},
	} {
		if got := isApplicationRecord(row.isCommit, row.attachment); got != row.want {
			t.Errorf("%s: isApplicationRecord answered %v, want %v", row.name, got, row.want)
		}
	}
}

// aad_mls held against a TRANSCRIPTION of MASTER section 8.4.2, and not against itself.
//
// WITHOUT THIS, THE AAD IS UNPINNED. Both ends of this package call one function, so a label spelled
// differently, a digest taken over the wrong preimage or an AAD_body swapped for a hash of it would
// agree with itself forever and be discovered by a second implementation. That is the exact failure
// keyschedule_test.go, recordkey_test.go and handle_test.go exist to close for their own
// derivations, and this is the fourth member of that family.
//
// The label is written out here rather than read off aadMlsLabel for the same reason every other
// transcription in this package is: reading it off the package would move both halves together.
func TestAadMlsIsMasterSection842sDigest(t *testing.T) {
	const label = "URmessage/v1/aad/mls"
	for _, binding := range []message.BodyBinding{
		{RetentionClass: message.RetentionDurable},
		{
			GroupId:        [32]byte{0x01, 0x02},
			SenderHandle:   [16]byte{0xAA},
			Epoch:          9,
			StreamIndex:    4096,
			RetentionClass: message.RetentionEph,
			EphBucket:      3,
			EphWindow:      1 << 33,
		},
	} {
		aadBody, err := message.AADBody(RecordAeadAlgId, binding)
		if err != nil {
			t.Fatalf("AADBody: %v", err)
		}
		want := sha256.Sum256(append([]byte(label), aadBody...))
		got, err := aadMls(binding)
		if err != nil {
			t.Fatalf("aadMls: %v", err)
		}
		if got != want {
			t.Errorf("aadMls answered %x and MASTER section 8.4.2's H(%q | AAD_body) is %x", got, label, want)
		}
		if len(got) != 32 {
			t.Errorf("aad_mls is %d octets and MASTER section 8.4.2 fixes it at 32", len(got))
		}
	}

	// AND IT IS NOT THE PREIMAGE ITSELF, nor an unlabelled digest, which are the two shapes an
	// edit reaches for. Both would be self-consistent across this package's own two ends.
	binding := message.BodyBinding{RetentionClass: message.RetentionDurable, StreamIndex: 7}
	aadBody, err := message.AADBody(RecordAeadAlgId, binding)
	if err != nil {
		t.Fatalf("AADBody: %v", err)
	}
	got, err := aadMls(binding)
	if err != nil {
		t.Fatalf("aadMls: %v", err)
	}
	if bytes.Equal(got[:], aadBody) {
		t.Error("aad_mls is AAD_body itself; MASTER section 8.4.2 hashes it, and the 256 octet rung is why")
	}
	if unlabelled := sha256.Sum256(aadBody); got == unlabelled {
		t.Error("aad_mls is an UNLABELLED digest of AAD_body; the domain separation label is what keeps this preimage out of every other digest in the system")
	}
	// and every field of AAD_body reaches it, which is what "the six fields that fix a record's
	// identity and position" means once it is a comparison rather than a sentence.
	base, err := aadMls(message.BodyBinding{RetentionClass: message.RetentionDurable})
	if err != nil {
		t.Fatalf("aadMls: %v", err)
	}
	for name, moved := range map[string]message.BodyBinding{
		"group_id":        {RetentionClass: message.RetentionDurable, GroupId: [32]byte{0x01}},
		"sender_handle":   {RetentionClass: message.RetentionDurable, SenderHandle: [16]byte{0x01}},
		"epoch":           {RetentionClass: message.RetentionDurable, Epoch: 1},
		"stream_index":    {RetentionClass: message.RetentionDurable, StreamIndex: 1},
		"retention_class": {RetentionClass: message.RetentionPermanent},
		"eph_window":      {RetentionClass: message.RetentionDurable, EphWindow: 1},
	} {
		got, err := aadMls(moved)
		if err != nil {
			t.Fatalf("aadMls with %s moved: %v", name, err)
		}
		if got == base {
			t.Errorf("moving %s does not move aad_mls, so a frame signed for one record's position verifies at another's", name)
		}
	}
}

// ---------------------------------------------------------------------------
// the size ladder, MEASURED HERE
// ---------------------------------------------------------------------------

// The usable application body per rung once the frame is inside it. MASTER section 8.4.4's column,
// RE-MEASURED by the case below rather than transcribed: if this tree and the ruling disagree, the
// case is what says so.
//
// It is a var and not a const because seal_test.go's minimality clause reads it, and a rung's
// capacity is now a property of the frame rather than of the ladder.
var applicationBodyCapacity = []int{59, 826, 3898, 16186, 65334}

// The frame's overhead over the application plaintext, which is a STEP FUNCTION and not a
// constant: RFC 9420's varint prefix widens at 64 and again at 16,384, and the frame carries two
// of them -- one around the ciphertext and one around the application data inside it.
var applicationFrameOverhead = []struct {
	plaintext int
	overhead  int
}{
	{0, 193}, {1, 193}, {63, 193}, {64, 194}, {16383, 196}, {16384, 198}, {65000, 198},
}

// THE QUERY, published beside the numbers: Protect at each length over a real two member group and
// walk the largest plaintext whose protected form fits rung - lpPrefixBytes.
//
// It is a two member group and a thirty two octet group id because both are inputs to the frame's
// length -- group_id is carried inside the PrivateMessage under a varint, and a group id of a
// different width moves every row. The walk is a bisection rather than a scan because the 64 KiB
// rung would otherwise cost sixty five thousand Protect calls, each of which consumes a ratchet
// generation.
//
// WHAT THE COLUMN COSTS, stated by the case that measures it: the 256 octet rung falls from 252
// usable octets to 59. A text longer than about 59 ASCII characters -- fifteen to twenty CJK
// characters or emoji -- now pays the 1 KiB rung, which is 1,040 stored octets where it paid 272.
// That is 3.8x for a large fraction of real traffic and it is the honest headline of this ruling.
func TestTheSizeLadderCostOfTheInnerFrameIsMeasuredHere(t *testing.T) {
	pair := newTestPair(t, "size-ladder")
	if len(applicationBodyCapacity) != int(message.SizeBucketBlob) {
		t.Fatalf("the ladder has %d rungs below the blob rung and this column has %d entries",
			message.SizeBucketBlob, len(applicationBodyCapacity))
	}
	for bucket := message.SizeBucket(0); bucket < message.SizeBucketBlob; bucket += 1 {
		rung := message.SizeBucketBytes(bucket)
		measured := -1
		low, high := 0, rung
		for low <= high {
			middle := (low + high) / 2
			framed, err := protectLength(t, pair, middle)
			if err != nil {
				t.Fatalf("Protect over a %d octet plaintext: %v", middle, err)
			}
			if framed+lpPrefixBytes <= rung {
				measured = middle
				low = middle + 1
			} else {
				high = middle - 1
			}
		}
		if measured != applicationBodyCapacity[bucket] {
			t.Errorf("rung %d (%d octets) carries %d octets of application body and this file's column says %d",
				bucket, rung, measured, applicationBodyCapacity[bucket])
		}
		t.Logf("rung %d: %d octets of ct_body plaintext, %d usable before this ruling, %d after -- %d lost",
			bucket, rung, rung-lpPrefixBytes, measured, rung-lpPrefixBytes-measured)
	}
	for _, step := range applicationFrameOverhead {
		framed, err := protectLength(t, pair, step.plaintext)
		if err != nil {
			t.Fatalf("Protect over a %d octet plaintext: %v", step.plaintext, err)
		}
		if framed-step.plaintext != step.overhead {
			t.Errorf("a %d octet plaintext frames to %d octets, an overhead of %d, and this file says %d",
				step.plaintext, framed, framed-step.plaintext, step.overhead)
		}
	}
}

// AND THE MEASUREMENT THE DIGEST WAS CHOSEN ON, which is the one number a reader is most likely to
// take on trust: carried VERBATIM rather than hashed, AAD_body's 104 octets leave the 256 octet
// rung carrying NO APPLICATION BODY AT ALL -- not a short one, not a zero length one.
//
// It is measured rather than argued because the alternative was a real candidate and the
// difference between the two columns is what decided it. A rung that carries nothing turns every
// reaction, receipt and typing indicator -- the whole of the next ruling's feature set, all of them
// tens of octets -- into a 1 KiB record.
func TestCarryingAadBodyVerbatimWouldLeaveThe256RungCarryingNothing(t *testing.T) {
	pair := newTestPair(t, "verbatim-aad")
	verbatim, err := message.AADBody(RecordAeadAlgId, message.BodyBinding{
		RetentionClass: message.RetentionDurable,
	})
	if err != nil {
		t.Fatalf("AADBody: %v", err)
	}
	if len(verbatim) != 104 {
		t.Errorf("AAD_body is %d octets and the ruling's measurement is 104", len(verbatim))
	}
	rung := message.SizeBucketBytes(message.SizeBucket256)
	empty, err := pair.chain.founder.Protect(verbatim, nil)
	if err != nil {
		t.Fatalf("Protect a zero length plaintext under a verbatim AAD_body: %v", err)
	}
	if len(empty)+lpPrefixBytes <= rung {
		t.Errorf("a zero length plaintext under a verbatim AAD_body frames to %d octets and fits the %d octet rung; the whole argument for hashing the aad is that it does not",
			len(empty), rung)
	}
	hashed, err := pair.chain.founder.Protect(make([]byte, 32), nil)
	if err != nil {
		t.Fatalf("Protect a zero length plaintext under a 32 octet aad: %v", err)
	}
	t.Logf("256 octet rung, %d octets of plaintext available: verbatim AAD_body needs %d for an EMPTY body, a 32 octet digest needs %d, so the digest buys %d usable octets and the verbatim form buys none",
		rung-lpPrefixBytes, len(empty), len(hashed), applicationBodyCapacity[0])
}

// The 198 octet band ledger open item 203 is about: bodies that fit before this ruling and do not
// fit after, whose only destination is a blob rung that is not built.
//
// It is a case rather than a note because it is the one place the ruling REMOVES a capability, and
// because the refusal a caller meets is the one it already met one octet further along -- so
// without this, the band would be invisible until somebody sent a 65 KiB message.
func TestTheNinetyEightOctetBandAtTheCeilingNoLongerFits(t *testing.T) {
	fixture := newTestSession(t, "the-64k-ceiling")
	rung := message.SizeBucketBytes(message.SizeBucket64K)
	for _, length := range []int{applicationBodyCapacity[message.SizeBucket64K] + 1, rung - lpPrefixBytes} {
		body := make([]byte, length)
		if _, err := fixture.session.SealRecord(message.RetentionDurable, 0, false,
			[]byte("head"), body, 0, nil); !errors.Is(err, ErrBodyTooLong) {
			t.Errorf("a %d octet body answered %v, want ErrBodyTooLong; it fitted the 64 KiB rung before MASTER section 8.4 and its only destination now is the blob rung, which is ledger open item 203",
				length, err)
		}
	}
	// and the top of the band still seals, so the boundary is the boundary and not the whole rung.
	body := make([]byte, applicationBodyCapacity[message.SizeBucket64K])
	record, err := fixture.session.SealRecord(message.RetentionDurable, 0, false, []byte("head"), body, 0, nil)
	if err != nil {
		t.Fatalf("a body of exactly the 64 KiB rung's new capacity did not seal: %v", err)
	}
	if record.Header.SizeBucket != message.SizeBucket64K {
		t.Errorf("a body of the 64 KiB rung's capacity landed on rung %d", record.Header.SizeBucket)
	}
	t.Logf("bodies of %d..%d octets fitted before this ruling and do not fit after; the band is %d octets wide",
		applicationBodyCapacity[message.SizeBucket64K]+1, rung-lpPrefixBytes,
		rung-lpPrefixBytes-applicationBodyCapacity[message.SizeBucket64K])
}

// A body no rung could hold under ANY framing costs neither a stream index nor an MLS generation.
//
// THIS CASE EXISTS BECAUSE THE CLAUSE IT HOLDS DEFENDED NOTHING WITHOUT IT, measured: deleting
// newRecordBuilderOnLoop's early bucketForBody refusal left the whole of ./messagegroup/ green.
// The clause is the half of the ladder refusal that can still be taken BEFORE anything is spent --
// MASTER section 8.4 moved the real bucket behind the frame, so the rung is now chosen after the
// index is reserved and after Protect has consumed a generation, and without the early refusal a
// caller handing in a megabyte would burn one of each on every attempt.
//
// WHAT IT DOES NOT COVER, and the second clause says so rather than leaving it implied: the 198
// octet band at the ceiling passes the early refusal and fails the real one, so a body in THAT
// band does spend both. That is ledger open item 203 and it is the price of the frame sitting
// inside the rung.
func TestABodyNoRungCouldHoldCostsNeitherAnIndexNorAGeneration(t *testing.T) {
	fixture := newTestSession(t, "too-long-costs-nothing")
	tooLong := make([]byte, message.SizeBucketBytes(message.SizeBucket64K)+1)
	if _, err := fixture.session.SealRecord(message.RetentionDurable, 0, false,
		[]byte("head"), tooLong, 0, nil); !errors.Is(err, ErrBodyTooLong) {
		t.Fatalf("a body longer than the largest rung answered %v, want ErrBodyTooLong", err)
	}
	record, err := fixture.session.SealRecord(message.RetentionDurable, 0, false,
		[]byte("head"), []byte("body"), 0, nil)
	if err != nil {
		t.Fatalf("SealRecord after the refusal: %v", err)
	}
	// THE FIRST INDEX THIS RESERVER HANDS OUT IS 1 AND NOT 0, measured rather than assumed: the
	// fake hands out the first index above its high water and its high water starts at zero. So
	// "nothing was spent" is "the next record is still the first one".
	if record.Header.StreamIndex != 1 {
		t.Errorf("the first record sealed after a refused over-long body is at stream_index %d, want 1; the refusal must be taken before the reservation, or a caller that hands in a body no rung can hold burns one index and one MLS generation per attempt",
			record.Header.StreamIndex)
	}

	// and the band that DOES spend them, which is item 203 held as a measurement rather than as
	// a note: this body passes the early refusal, is framed, and fails the real one.
	band := newTestSession(t, "the-203-band")
	inBand := make([]byte, applicationBodyCapacity[message.SizeBucket64K]+1)
	if _, err := band.session.SealRecord(message.RetentionDurable, 0, false,
		[]byte("head"), inBand, 0, nil); !errors.Is(err, ErrBodyTooLong) {
		t.Fatalf("a body in the 203 band answered %v, want ErrBodyTooLong", err)
	}
	after, err := band.session.SealRecord(message.RetentionDurable, 0, false,
		[]byte("head"), []byte("body"), 0, nil)
	if err != nil {
		t.Fatalf("SealRecord after the band refusal: %v", err)
	}
	if after.Header.StreamIndex != 2 {
		t.Errorf("a body in the 203 band left the next record at stream_index %d and the measured answer is 2; if it is 1 the early refusal has widened to cover the band, and this comment and ledger open item 203 are what have to change",
			after.Header.StreamIndex)
	}
	t.Logf("a body no rung could hold spends nothing; a body in the %d octet band at the ceiling spends one stream index and one MLS generation (ledger open item 203)",
		message.SizeBucketBytes(message.SizeBucket64K)-lpPrefixBytes-applicationBodyCapacity[message.SizeBucket64K])
}

// octet_length(ct_body) does not move at any rung, which is the claim MASTER section 8.4.4 makes
// about what this ruling does NOT cost and is the one a codec, a schema and a CHECK all rest on.
//
// The rung is what is sealed and the frame sits inside it, so the ladder's own arithmetic is
// untouched: message.SizeBucketCtBodyBytes is an EQUALITY the codec enforces, and a record whose
// ct_body were the frame's length plus a tag would be a record EncodeRecord refuses.
func TestTheFrameDoesNotMoveOctetLengthOfCtBody(t *testing.T) {
	fixture := newTestSession(t, "ct-body-length")
	for bucket := message.SizeBucket(0); bucket < message.SizeBucketBlob && bucket < 3; bucket += 1 {
		body := make([]byte, applicationBodyCapacity[bucket])
		record, err := fixture.session.SealRecord(message.RetentionDurable, 0, false,
			[]byte("head"), body, 0, nil)
		if err != nil {
			t.Fatalf("SealRecord over rung %d's capacity: %v", bucket, err)
		}
		if record.Header.SizeBucket != bucket {
			t.Errorf("a body of rung %d's measured capacity landed on rung %d", bucket, record.Header.SizeBucket)
		}
		if want := message.SizeBucketCtBodyBytes(record.Header.SizeBucket); len(record.CtBody) != want {
			t.Errorf("rung %d: ct_body is %d octets and the ladder fixes it at %d",
				bucket, len(record.CtBody), want)
		}
		if _, err := message.EncodeRecord(record); err != nil {
			t.Errorf("rung %d: the record is not one the codec accepts: %v", bucket, err)
		}
	}
}

// ---------------------------------------------------------------------------
// message_id, MASTER section 8.4.5
// ---------------------------------------------------------------------------

// The derivation held against a transcription of MASTER section 8.4.5, written out here rather
// than read off handle.go.
//
// It is the discipline every KAT in this package is written under and the reason is the same:
// reaching for messageIdInfo would let a label change move both halves together and leave this
// file green over an identifier no second implementation computes. The expansion goes through the
// reference HKDF keyschedule_test.go already writes out from RFC 5869.
func TestMessageIdIsMasterSection845sDerivation(t *testing.T) {
	groupHandleKey := make([]byte, 32)
	for i := range groupHandleKey {
		groupHandleKey[i] = byte(0x40 + i)
	}
	groupId := [32]byte{}
	for i := range groupId {
		groupId[i] = byte(i)
	}
	senderHandle := [16]byte{}
	for i := range senderHandle {
		senderHandle[i] = byte(0xB0 + i)
	}
	for _, streamIndex := range []uint64{0, 1, 4096, 1 << 40} {
		info := []byte("mid/v1")
		info = append(info, messageIdReferenceLP(groupId[:])...)
		info = append(info, messageIdReferenceLP(senderHandle[:])...)
		info = append(info, messageIdReferenceU64(streamIndex)...)
		// 6 + (4+32) + (4+16) + 8 = 70, stated by MASTER section 8.4.5 and asserted rather
		// than assumed: a prefix of the wrong width is an info of the wrong length before it
		// is an identifier of the wrong value.
		if len(info) != 70 {
			t.Fatalf("the info is %d octets and MASTER section 8.4.5 makes it 70", len(info))
		}
		want := keyScheduleReferenceExpand(groupHandleKey, info, 32)
		got := MessageId(groupHandleKey, groupId, senderHandle, streamIndex)
		if !bytes.Equal(got[:], want) {
			t.Errorf("stream index %d: MessageId answered %x and MASTER section 8.4.5 gives %x",
				streamIndex, got, want)
		}
	}
}

// Every input is live, and the key is one of them.
//
// A derivation that ignored an argument would be an identifier two different messages share, and
// the two that matter most are the two a reader is least likely to check: stream_index, because
// it is the only thing that distinguishes one sender's messages from each other, and
// group_handle_key, because an unkeyed id is one the message server computes for every record it
// stores.
func TestEveryInputToAMessageIdMovesIt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x40 + i)
	}
	groupId := [32]byte{0x11}
	handle := [16]byte{0x22}
	base := MessageId(key, groupId, handle, 7)
	otherKey := append([]byte(nil), key...)
	otherKey[0] ^= 0x01
	otherGroup := groupId
	otherGroup[31] ^= 0x01
	otherHandle := handle
	otherHandle[15] ^= 0x01
	for name, got := range map[string][32]byte{
		"a different group_handle_key": MessageId(otherKey, groupId, handle, 7),
		"a different group_id":         MessageId(key, otherGroup, handle, 7),
		"a different sender_handle":    MessageId(key, groupId, otherHandle, 7),
		"the next stream_index":        MessageId(key, groupId, handle, 8),
	} {
		if got == base {
			t.Errorf("%s produces the same message_id, so that input is not in the derivation", name)
		}
	}
}

// BOTH SIDES DERIVE THE SAME OCTETS FROM THE SAME AUTHENTICATED INPUTS, which is the whole of what
// makes this an id rather than a label.
//
// The sender has the reserved stream_index before it seals -- so a reply can name its own parent
// optimistically -- and a receiver reads all three inputs off the PLAINTEXT header, so it needs
// neither the body nor any epoch secret. This case is the second half stated as a comparison: the
// id the sealer could compute equals the id an opener computes off the record, and the opener's
// side reaches nothing but header fields.
//
// AND IT IS NOT record_id. The server assigns that after acceptance, so a client has nothing to
// quote in the record it is sealing; the case asserts the two differ rather than leaving a reader
// to infer it.
func TestAMessageIdIsComputableBeforeTheSendAndFromTheHeaderAlone(t *testing.T) {
	pair := newTestPair(t, "message-id-both-sides")
	pair.trackDurable(t)
	record, err := pair.sender.SealRecord(message.RetentionDurable, 0, false,
		[]byte("head"), []byte("body"), 0, nil)
	if err != nil {
		t.Fatalf("SealRecord: %v", err)
	}
	senderHandle, err := pair.sender.SenderHandle()
	if err != nil {
		t.Fatalf("the sender's own handle: %v", err)
	}
	// the sender's side: the three values it holds before it seals.
	fromSender := MessageId(pair.chain.groupHandleKey, record.Header.GroupId, senderHandle,
		record.Header.StreamIndex)
	// the opener's side: three PLAINTEXT header fields and the group handle key every member
	// holds. Nothing here opens anything.
	fromOpener := MessageId(pair.chain.groupHandleKey, record.Header.GroupId,
		record.Header.SenderHandle, record.Header.StreamIndex)
	if fromSender != fromOpener {
		t.Errorf("the sender computes %x and an opener reading the header computes %x", fromSender, fromOpener)
	}
	// and the record's own body is not an input, which is what lets an EPH row whose ct_body has
	// been erased keep its id.
	erased := *record
	erased.CtBody = nil
	if again := MessageId(pair.chain.groupHandleKey, erased.Header.GroupId,
		erased.Header.SenderHandle, erased.Header.StreamIndex); again != fromOpener {
		t.Error("the message_id of a record whose ct_body has been erased is not the id it had")
	}
	// it is not record_id, which the server assigns after acceptance -- so a client sealing a
	// record has nothing to quote of it, and MASTER section 8 keeps it out of every preimage for
	// exactly that reason.
	if record.RecordId != 0 {
		t.Errorf("a record this package sealed carries record_id %d; the server assigns it after acceptance", record.RecordId)
	}
	t.Logf("message_id %x, computed by the sender before the send and by an opener from three plaintext header fields",
		fromOpener)
}

// driftingHandle is a GroupHandle whose Unprotect answers a DIFFERENT sender leaf, or a different
// aad, from the one the pre-ratchet peek reads off the same octets.
//
// IT EXISTS TO MAKE THE SECOND READING SEPARABLE. unframeBodyOnLoop takes MASTER section 8.4.3's
// two refusals twice: once on the peek, which moves no ratchet and is therefore where a refusal is
// free, and once on what Unprotect answers, which is the reading the signature covers and is the
// one that decides. Over the real engine the two agree by construction -- mls's
// TestThePeekAgreesWithTheOpenOnEveryMessageThatOpens is that, swept -- so over the real engine,
// deleting the second reading turns nothing red, and a clause nothing can turn red is a clause the
// suite does not hold. This is the input that separates them: an engine whose two answers differ.
//
// It is not a hypothetical about a hostile engine. It is the shape of the bug the pre-filter could
// introduce -- a peek that drifted from the open would silently become the whole rule -- and the
// refusal below is what says the open's answer is still the one being judged.
type driftingHandle struct {
	GroupHandle
	leafDrift uint32
	aadDrift  bool
}

// Close is a NO-OP, because three sessions in this case share one handle and a GroupSession closes
// the handle it was built over. Without it the first row's cleanup would close the group the second
// row is about, and the second row would report "the group is closed" -- a true sentence about the
// fixture standing where the property should be.
func (self *driftingHandle) Close() error { return nil }

func (self *driftingHandle) Unprotect(frame []byte) ([]byte, []byte, uint32, error) {
	aad, plaintext, senderLeaf, err := self.GroupHandle.Unprotect(frame)
	if err != nil {
		return nil, nil, 0, err
	}
	if self.aadDrift && 0 < len(aad) {
		aad = append([]byte(nil), aad...)
		aad[0] ^= 0xff
	}
	return aad, plaintext, senderLeaf + self.leafDrift, err
}

// The second reading is the one that decides, and an engine whose two readings disagree is refused.
//
// The control comes first and it is the whole reason the case is readable: the SAME session over
// the SAME handle with no drift opens the record. So the refusals below are about the drift and not
// about a fixture that never worked.
func TestTheReadingThatDecidesIsTheOneTheSignatureCovers(t *testing.T) {
	chain := newTwoEngineChain(t, "the-reading-that-decides")
	t.Cleanup(chain.close)
	senderLeaf := chain.founder.OwnLeafIndex()

	open := func(t *testing.T, drift *driftingHandle, record *message.Record) ([]byte, error) {
		t.Helper()
		session, err := NewGroupSession(drift, chain.pqSecret, chain.groupHandleKey,
			newStreamIndexMemory(), testClock(), testServerNonce())
		if err != nil {
			t.Fatalf("a session over the drifting handle: %v", err)
		}
		defer session.Close()
		if err := session.TrackSender(senderLeaf, message.RetentionDurable, 0, 0, 0); err != nil {
			t.Fatalf("TrackSender: %v", err)
		}
		_, bodyPlain, err := session.OpenRecord(record)
		return bodyPlain, err
	}

	rows := []struct {
		what     string
		drift    *driftingHandle
		sentinel error
	}{
		{what: "no drift, the control", drift: &driftingHandle{GroupHandle: chain.joined}, sentinel: nil},
		{
			what:     "Unprotect answers another leaf than the peek read",
			drift:    &driftingHandle{GroupHandle: chain.joined, leafDrift: 1},
			sentinel: ErrRecordSenderBinding,
		},
		{
			what:     "Unprotect answers another aad than the peek read",
			drift:    &driftingHandle{GroupHandle: chain.joined, aadDrift: true},
			sentinel: ErrRecordPositionBinding,
		},
	}
	for _, row := range rows {
		record, err := chain.founderSession.SealRecord(message.RetentionDurable, 0, false,
			[]byte("head"), []byte("a message the sender really wrote"), 0, nil)
		if err != nil {
			t.Fatalf("%s: SealRecord: %v", row.what, err)
		}
		bodyPlain, err := open(t, row.drift, record)
		if row.sentinel == nil {
			if err != nil {
				t.Fatalf("%s: %v", row.what, err)
			}
			if !bytes.Equal(bodyPlain, []byte("a message the sender really wrote")) {
				t.Fatalf("%s: the control opened to %q", row.what, bodyPlain)
			}
			continue
		}
		if !errors.Is(err, row.sentinel) {
			t.Errorf("%s: OpenRecord answered %v, want %v. The pre-ratchet peek is a filter and never the answer; the reading the signature covers is what MASTER section 8.4.3 is taken on",
				row.what, err, row.sentinel)
		}
		if bodyPlain != nil {
			t.Errorf("%s: the refusal returned %d octets of body", row.what, len(bodyPlain))
		}
	}
}

// ---------------------------------------------------------------------------
// the arm of MASTER section 8.4.1's table, and who picks it
// ---------------------------------------------------------------------------

// The arm is chosen by two fields no signature covers, so the refusals of MASTER section 8.4.3 were
// OPT-OUT until the door split. This is that, measured from the attacker's side.
//
// isApplicationRecord reads is_commit and the encoded server attachment. Both live in AAD_head,
// AAD_head is sealed under record_key[n], and record_key[0] is RecordKeyZero(class_key, leaf) --
// a class key every member holds and a leaf NUMBER. So the member that seals a record decides
// which row of the table it takes, and before the split a member that did not want to be
// signature-checked simply set is_commit: OpenRecord answered that member's own octets under
// whatever sender_handle it liked, with no signature anywhere on the path.
//
// WHAT IS ASSERTED IS BOTH HALVES, and the second is the uncomfortable one. The message door now
// refuses both ceremony arms by name -- that is the repair. The ceremony door still answers the
// forged octets, because the ceremony arm carries no signature and cannot be authenticated here;
// that is MEASURED and printed rather than left to a reader, because a case that only showed the
// refusal would read as though the arm had been closed. Open item MG-5 is what a ruling owes it.
func TestTheArmOfTheTableIsChosenBySomethingNoSignatureCovers(t *testing.T) {
	pair := newTestPair(t, "the-arm-is-chosen")
	forgerSession := pair.opener
	victimLeaf := pair.senderLeaf
	opener := pair.sender
	if err := opener.TrackSender(victimLeaf, message.RetentionDurable, 0, 0, 0); err != nil {
		t.Fatalf("A tracks its own ladder: %v", err)
	}

	wrap, err := message.EncodeServerAttachment(&message.ServerAttachment{
		Kind: message.AttachmentWrap,
		Wrap: &message.WrapTag{WrapTargetHandle: make([]byte, 16), Epoch: 1},
	})
	if err != nil {
		t.Fatalf("EncodeServerAttachment: %v", err)
	}

	rows := []struct {
		what       string
		isCommit   bool
		attachment []byte
		index      uint64
	}{
		{what: "is_commit set", isCommit: true, attachment: nil, index: 0},
		{what: "a server attachment set", isCommit: false, attachment: wrap, index: 1},
	}
	for _, row := range rows {
		body := []byte("OCTETS B CHOSE, ATTRIBUTED TO A")
		forged := repairForgeRecordArm(t, forgerSession, victimLeaf, row.index,
			row.isCommit, row.attachment, []byte("a head attributed to A"), body)
		if forged.Header.SenderHandle != SenderHandle(forgerSession.groupHandleKey, victimLeaf) {
			t.Fatalf("%s: the forged record does not carry A's sender_handle", row.what)
		}

		// THE REPAIR. The door that returns a message refuses this record, so no call named for
		// opening a message can be made to answer octets no member signed.
		headPlain, bodyPlain, err := opener.OpenRecord(forged)
		if !errors.Is(err, ErrRecordNotAnApplicationRecord) {
			t.Errorf("%s: a record B forged at A's handle with no signature anywhere opened at the MESSAGE door with %v; want ErrRecordNotAnApplicationRecord. A rule an attacker can opt out of is not a rule",
				row.what, err)
		}
		if headPlain != nil || bodyPlain != nil {
			t.Errorf("%s: the refusal returned %d octets of head and %d of body",
				row.what, len(headPlain), len(bodyPlain))
		}

		// AND THE PART THAT IS NOT CLOSED, measured rather than described. The ceremony arm has
		// no signature to check -- Spec A section 5.11 step 5 -- so the ceremony door does answer
		// the attacker's octets under the victim's handle. Its name is the whole of what says so,
		// and nothing that renders a message may call it.
		_, ceremonyBody, err := opener.OpenCeremonyRecord(forged)
		if err != nil {
			t.Fatalf("%s: the ceremony door refused a well formed ceremony record: %v", row.what, err)
		}
		if !bytes.Equal(ceremonyBody, body) {
			t.Fatalf("%s: the ceremony door answered %q", row.what, ceremonyBody)
		}
		t.Logf("%s: the message door refuses it, and the ceremony door answers %q under a sender_handle B does not own. The ceremony arm is authenticated by nothing and open item MG-5 is what a ruling owes it",
			row.what, ceremonyBody)
	}
}

// ---------------------------------------------------------------------------
// MASTER section 8.4.5's message_id, and the door it had none of
// ---------------------------------------------------------------------------

// The sender and an opener compute one id for one record THROUGH THE SESSION, which is the surface
// the derivation had none of.
//
// messagegroup.MessageId has been exported and correct since the ruling and had NO CALLER anywhere
// in connect or in sdk -- so "both sides derive the same value" was a property of a function rather
// than of the build, and a reply, a reaction or a read cursor had nothing to name. What is held
// here is the id coming out of the two sessions that actually have the record: the sender, from the
// record it just sealed and before any submit, and the opener, from the header it parsed.
//
// AND IT IS THE FREE FUNCTION'S ANSWER AND NOT A SECOND DERIVATION. The door supplies the key and
// the header supplies the other three inputs; a door that expanded anything of its own would be a
// second implementation of a formula three documents already state.
func TestTheMessageIdDoorAnswersOneIdAtTheSenderAndAtTheOpener(t *testing.T) {
	pair := newTestPair(t, "message-id-door")
	pair.trackDurable(t)

	record, err := pair.sender.SealRecord(message.RetentionDurable, 0, false,
		[]byte("head"), []byte("a message with an id"), 0, nil)
	if err != nil {
		t.Fatalf("SealRecord: %v", err)
	}
	fromSender, err := pair.sender.MessageIdOf(&record.Header)
	if err != nil {
		t.Fatalf("the sender's MessageIdOf: %v", err)
	}
	fromOpener, err := pair.opener.MessageIdOf(&record.Header)
	if err != nil {
		t.Fatalf("the opener's MessageIdOf: %v", err)
	}
	if fromSender != fromOpener {
		t.Fatalf("the sender derives %x and the opener derives %x for one record", fromSender, fromOpener)
	}
	want := MessageId(pair.chain.groupHandleKey, record.Header.GroupId,
		record.Header.SenderHandle, record.Header.StreamIndex)
	if fromSender != want {
		t.Fatalf("the door answers %x and MASTER section 8.4.5's derivation answers %x; the door must be that formula and not a second one",
			fromSender, want)
	}
	// and the record OPENS, which is what makes the id worth having: an id names a message, and
	// what says the message is that member's is R1 and R2.
	if _, gotBody, err := pair.opener.OpenRecord(record); err != nil {
		t.Fatalf("the record the id names does not open: %v", err)
	} else if !bytes.Equal(gotBody, []byte("a message with an id")) {
		t.Fatalf("the record opened to %q", gotBody)
	}
	t.Logf("message_id %x, taken through the session at both ends rather than through a formula neither end calls", fromSender)

	// THE INDEX IS AN INPUT, which one id cannot say. Two positions of one sender are two ids.
	moved := record.Header
	moved.StreamIndex += 1
	atNext, err := pair.sender.MessageIdOf(&moved)
	if err != nil {
		t.Fatalf("MessageIdOf at the next index: %v", err)
	}
	if atNext == fromSender {
		t.Fatal("two stream indices of one sender answer one id, so the index is not an input")
	}

	// AND A HEADER FROM ANOTHER GROUP IS REFUSED rather than answered. The formula takes the
	// group id as an input, so a foreign header would produce a perfectly well formed id under
	// THIS group's key -- a value no member of either group computes, with no error anywhere.
	foreign := record.Header
	foreign.GroupId[0] ^= 0xff
	if _, err := pair.sender.MessageIdOf(&foreign); !errors.Is(err, ErrRecordNotForThisSession) {
		t.Errorf("a header naming another group answered %v, want ErrRecordNotForThisSession", err)
	}
	if _, err := pair.sender.MessageIdOf(nil); !errors.Is(err, message.ErrRecordNil) {
		t.Errorf("a nil header answered %v, want message.ErrRecordNil", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// forgeBodyBinding is the BodyBinding repairForgeRecord's header produces, built here so a case
// that hands Protect an aad and a case that builds the record cannot disagree about which
// position that record is at.
func forgeBodyBinding(session *GroupSession, leaf uint32, streamIndex uint64) message.BodyBinding {
	return message.BodyBinding{
		GroupId:        session.groupId,
		SenderHandle:   SenderHandle(session.groupHandleKey, leaf),
		Epoch:          session.epoch,
		StreamIndex:    streamIndex,
		RetentionClass: message.RetentionDurable,
		EphBucket:      0,
		EphWindow:      0,
	}
}

// protectLength answers how many octets one plaintext frames to, over the pair's founder handle.
//
// It takes a fresh aad of the width aad_mls is at every call, because the aad's LENGTH is inside
// the frame and a case measuring the ladder under a shorter one would be measuring a different
// ladder.
func protectLength(t *testing.T, pair *testPair, plaintext int) (int, error) {
	t.Helper()
	aad, err := aadMls(message.BodyBinding{RetentionClass: message.RetentionDurable})
	if err != nil {
		return 0, err
	}
	framed, err := pair.chain.founder.Protect(aad[:], make([]byte, plaintext))
	if err != nil {
		return 0, err
	}
	return len(framed), nil
}

// LP(x) and u64, written out here for the reason every label in a KAT is: a prefix width read off
// the package would move both halves of the comparison together.
func messageIdReferenceLP(x []byte) []byte {
	return append([]byte{byte(len(x) >> 24), byte(len(x) >> 16), byte(len(x) >> 8), byte(len(x))}, x...)
}

func messageIdReferenceU64(v uint64) []byte {
	out := make([]byte, 8)
	for i := range out {
		out[i] = byte(v >> (56 - 8*i))
	}
	return out
}

// ---------------------------------------------------------------------------
// the two denial channels a record's ACCEPTANCE and its REFUSAL used to open,
// and the one that is filed rather than closed
// ---------------------------------------------------------------------------

// censorshipKeySource lets a member choose the LEAF and the GENERATION an inner frame's sender data
// names, which is the whole of what the attack below needs.
//
// EVERY INPUT IT USES IS GROUP SHARED and that is the finding rather than the fixture. sender data
// is sealed under the epoch's sender_data_secret, which comes off the GroupHandle and which every
// member of the group holds, so the leaf and the generation inside it are values ANY member writes.
// The content is sealed under a key this source invents, so the frame will never open -- which is
// the point: the refusal has to land AFTER mls has been asked for the victim's key at the forged
// generation, because that ask is what used to move the victim's ratchet.
type censorshipKeySource struct {
	crypto     mls.CryptoProvider
	generation uint32
}

func (self *censorshipKeySource) NextMessageKey(mls.ContentType, mls.LeafIndex) ([]byte, []byte, uint32, error) {
	return bytes.Repeat([]byte{0x5a}, self.crypto.KeySize()),
		bytes.Repeat([]byte{0x5a}, self.crypto.NonceSize()), self.generation, nil
}

func (self *censorshipKeySource) MessageKey(mls.ContentType, mls.LeafIndex, uint32) ([]byte, []byte, error) {
	return nil, nil, errors.New("messagegroup: the forging source is a sender side source only")
}

func (self *censorshipKeySource) CommitMessageKey(mls.ContentType, mls.LeafIndex, uint32) error {
	return errors.New("messagegroup: the forging source is a sender side source only")
}

func (self *censorshipKeySource) EraseMessageKey(mls.ContentType, mls.LeafIndex, uint32) {}

// forgeFrameAtGeneration builds an inner MLS frame whose sender data names leaf and generation of
// the caller's choosing and whose cleartext authenticated_data is aad.
func forgeFrameAtGeneration(t *testing.T, handle GroupHandle, leaf uint32, generation uint32, aad []byte) []byte {
	t.Helper()
	contextBytes, err := handle.GroupContextBytes()
	if err != nil {
		t.Fatalf("GroupContextBytes: %v", err)
	}
	context := &mls.GroupContext{}
	if err := syntax.Unmarshal(contextBytes, context); err != nil {
		t.Fatalf("unmarshal the group context: %v", err)
	}
	crypto, err := mls.NewCryptoProvider(context.CipherSuite)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	senderDataSecret, err := handle.SenderDataSecret()
	if err != nil {
		t.Fatalf("SenderDataSecret: %v", err)
	}
	authContent := &mls.AuthenticatedContent{
		WireFormat: mls.WireFormatPrivateMessage,
		Content: mls.FramedContent{
			GroupId:           context.GroupId,
			Epoch:             context.Epoch,
			Sender:            mls.Sender{SenderType: mls.SenderTypeMember, LeafIndex: mls.LeafIndex(leaf)},
			AuthenticatedData: append([]byte(nil), aad...),
			ContentType:       mls.ContentTypeApplication,
			ApplicationData:   []byte("octets that will never open"),
		},
		Auth: mls.FramedContentAuthData{Signature: bytes.Repeat([]byte{0x11}, 64)},
	}
	private, err := mls.SealPrivateMessage(crypto, &censorshipKeySource{crypto: crypto, generation: generation},
		senderDataSecret, authContent, 0)
	if err != nil {
		t.Fatalf("SealPrivateMessage: %v", err)
	}
	frame, err := mls.MarshalMLSMessage(&mls.MLSMessage{
		Version: mls.ProtocolVersionMls10, WireFormat: mls.WireFormatPrivateMessage,
		PrivateMessage: private,
	})
	if err != nil {
		t.Fatalf("MarshalMLSMessage: %v", err)
	}
	return frame
}

// TestAForgedGenerationInTheFrameHeaderCostsTheTrueSenderNothing is the CRITICAL channel of the
// third pass over MASTER section 8.4, driven end to end through OpenRecord.
//
// WHY THE PRE-RATCHET PEEK CANNOT STOP IT, which is the sentence that makes this case necessary
// rather than a second reading of the two refusals next door. R1 is a function of the frame's
// sender leaf and R2 is a function of its cleartext authenticated_data, and the FORGER writes both.
// A member that sets the sender data to the victim's leaf, puts the record at the victim's
// sender_handle, and sets the frame's aad to the aad of the position it is putting the record at
// passes both refusals BY CONSTRUCTION. There is a third field in that sender data -- the
// GENERATION -- that nothing authenticates and nothing above mls can check, and mls reaches it
// before the content AEAD and before the signature.
//
// WHAT IT USED TO BUY. The victim's receiving ratchet stepped to the forged generation, retained
// the run it passed and pruned it; the content AEAD then failed and the record was refused with
// "mls: message does not decrypt". Nothing was ERASED and the keys were EVICTED, which is the same
// outcome for the victim: every generation below a head is consumed, so one forged header cost the
// victim its next message, two cost it 1,025 of them, and the refusal is taken inside
// unframeBodyOnLoop -- before this package's own Commit -- so the same record could be sent again
// at the SAME stream index forever. Measured before the repair: three forged records at one index
// cost the true sender four of its next four messages, and it never had to have written anything.
//
// THE VACUITY GUARD IS THE REFUSAL'S OWN SENTINEL. If the forged record were refused at R1 or R2
// then mls never saw the generation, this case would be driving the channel that was already
// closed, and it would pass on a build with the defect. So the refusal is required to be
// ErrRecordInnerFrame -- mls refusing the frame itself, which is refused BELOW the peek.
func TestAForgedGenerationInTheFrameHeaderCostsTheTrueSenderNothing(t *testing.T) {
	pair := newTestPair(t, "forged-generation")
	pair.trackDurable(t)

	// the true sender writes, and nobody has opened it yet -- a message in flight, the ordinary
	// case and the one with something to lose.
	plaintext := []byte("the message being censored")
	genuine, err := pair.sender.SealRecord(message.RetentionDurable, 0, false,
		[]byte("head"), plaintext, 0, nil)
	if err != nil {
		t.Fatalf("SealRecord: %v", err)
	}
	at := genuine.Header.StreamIndex + 1

	aad, err := aadMls(forgeBodyBinding(pair.opener, pair.senderLeaf, at))
	if err != nil {
		t.Fatalf("aadMls: %v", err)
	}
	frame := forgeFrameAtGeneration(t, pair.opener.handle, pair.senderLeaf, mls.MaxGenerationSkip, aad[:])
	forged := repairForgeRecord(t, pair.opener, pair.senderLeaf, at,
		[]byte("a head the attacker chose"), frame)

	if _, _, err := pair.opener.OpenRecord(forged); err == nil {
		t.Fatal("the forged record OPENED, which is a different and worse finding")
	} else if !errors.Is(err, ErrRecordInnerFrame) {
		t.Fatalf("the forged record was refused with %v, want ErrRecordInnerFrame: a refusal at R1 or R2 means mls never saw the forged generation and this case is not driving the channel it names",
			err)
	}

	// THE STAKE. The true sender's own message, written before any of this.
	_, body, err := pair.opener.OpenRecord(genuine)
	if err != nil {
		t.Fatalf("the true sender's genuine message is unopenable after ONE forged header: %v. No input an unauthenticated party controls may advance or prune another member's receiving ratchet",
			err)
	}
	if !bytes.Equal(body, plaintext) {
		t.Fatalf("the genuine message opened to %q, want %q", body, plaintext)
	}
}

// TestForgedGenerationsAreRepeatableAtOneStreamIndexAndCostNothing is the amplified form, and it is
// the one that says the repair holds against a member that keeps going rather than against one
// header.
//
// The refusal is taken before this package's own Commit, so the attacker's stream index is never
// spent and the same record shape can be re-sent at index 0 forever. On the build this closes each
// round advanced the victim's MLS receiving head by another MaxGenerationSkip; here each round has
// to cost nothing, and the victim then writes for the FIRST time -- so the case is pre-emptive,
// which the lift-and-re-envelope channel could not be.
func TestForgedGenerationsAreRepeatableAtOneStreamIndexAndCostNothing(t *testing.T) {
	pair := newTestPair(t, "forged-generation-rounds")
	pair.trackDurable(t)

	// the attacker moves FIRST. The victim has written nothing at all.
	const at = uint64(0)
	aad, err := aadMls(forgeBodyBinding(pair.opener, pair.senderLeaf, at))
	if err != nil {
		t.Fatalf("aadMls: %v", err)
	}
	const rounds = 3
	for round := 1; round <= rounds; round += 1 {
		frame := forgeFrameAtGeneration(t, pair.opener.handle, pair.senderLeaf,
			uint32(round)*mls.MaxGenerationSkip, aad[:])
		forged := repairForgeRecord(t, pair.opener, pair.senderLeaf, at,
			[]byte("a head the attacker chose"), frame)
		if _, _, err := pair.opener.OpenRecord(forged); err == nil {
			t.Fatalf("round %d: the forged record OPENED", round)
		} else if !errors.Is(err, ErrRecordInnerFrame) {
			t.Fatalf("round %d was refused with %v, want ErrRecordInnerFrame", round, err)
		}
	}

	// and NOW the victim writes, for the first time.
	for wrote := 0; wrote < 4; wrote += 1 {
		plaintext := fmt.Appendf(nil, "a message written after %d forged records", rounds)
		record, err := pair.sender.SealRecord(message.RetentionDurable, 0, false,
			[]byte("head"), plaintext, 0, nil)
		if err != nil {
			t.Fatalf("SealRecord %d: %v", wrote, err)
		}
		_, body, err := pair.opener.OpenRecord(record)
		if err != nil {
			t.Fatalf("message %d of the victim's is unopenable after %d forged records at one stream index: %v",
				wrote, rounds, err)
		}
		if !bytes.Equal(body, plaintext) {
			t.Fatalf("message %d opened to %q, want %q", wrote, body, plaintext)
		}
	}
}

// TestTheCeremonyDoorSpendsNoneOfTheHandleItNames is MG-5's DENIAL half, which that item filed as
// an attribution hole and measured only as attributed octets.
//
// WHAT THE OTHER HALF IS. openRecordOnLoop ran receivers.Commit for BOTH doors, and the ceremony arm
// takes no frame check at all -- unframeBodyOnLoop returns a ceremony body unchanged. Every key the
// two record AEADs use is group shared, so a member can seal a ceremony record at any other member's
// sender_handle at any index. Accepted, it committed the victim's ladder past the rung the victim's
// own next record needed: one squatted record per message, no lift, no genuine frame, no race, and
// the victim's record at that index answering ErrOutOfWindow forever.
//
// THE CONTROL IS THE ACCEPTANCE ITSELF. The ceremony record still opens, and to the attacker's own
// octets -- that is the attribution residual MG-5 files and this case does not repair it. What it
// requires is that the acceptance spends nothing of the handle it named.
func TestTheCeremonyDoorSpendsNoneOfTheHandleItNames(t *testing.T) {
	pair := newTestPair(t, "ceremony-ladder")
	pair.trackDurable(t)

	// the victim writes first so the index it is about to need is read off its own record rather
	// than assumed; the record is held back and opened at the end, which is what makes the squat
	// below a squat rather than a race.
	plaintext := []byte("the victim's own first message")
	genuine, err := pair.sender.SealRecord(message.RetentionDurable, 0, false,
		[]byte("head"), plaintext, 0, nil)
	if err != nil {
		t.Fatalf("SealRecord: %v", err)
	}
	at := genuine.Header.StreamIndex

	// that index, squatted by a ceremony record the attacker builds. is_commit puts it on the arm
	// OpenRecord refuses and OpenCeremonyRecord serves.
	chosen := []byte("octets the attacker chose")
	squat := repairForgeRecordArm(t, pair.opener, pair.senderLeaf, at, true, nil,
		[]byte("a head the attacker chose"), chosen)
	_, body, err := pair.opener.OpenCeremonyRecord(squat)
	if err != nil {
		t.Fatalf("the ceremony door refused the squatted record: %v; this case needs the ACCEPTANCE, because it is the acceptance that used to walk the ladder",
			err)
	}
	if !bytes.Equal(body, chosen) {
		t.Fatalf("the ceremony door answered %q, want %q", body, chosen)
	}

	// THE STAKE. The victim's own record at that same index.
	_, got, err := pair.opener.OpenRecord(genuine)
	if err != nil {
		t.Fatalf("the victim's own record at stream index %d no longer opens after a ceremony record was ACCEPTED there: %v. A door that authenticates nothing may not spend anything either",
			at, err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("the victim's record opened to %q, want %q", got, plaintext)
	}
}

// TestTheApplicationDoorStillSpendsTheRungItOpens is the other side of the case above, and without
// it that one is satisfied by a build whose ladder never moves at all.
//
// A ladder that committed nothing would have no replay guard and no ordering: the same record would
// open forever. So the arm that IS checked is required to spend its rung, which is what makes "the
// ceremony arm spends nothing" a statement about the arm rather than about the ladder.
func TestTheApplicationDoorStillSpendsTheRungItOpens(t *testing.T) {
	pair := newTestPair(t, "application-ladder")
	pair.trackDurable(t)

	record, err := pair.sender.SealRecord(message.RetentionDurable, 0, false,
		[]byte("head"), []byte("a message that spends its rung"), 0, nil)
	if err != nil {
		t.Fatalf("SealRecord: %v", err)
	}
	if _, _, err := pair.opener.OpenRecord(record); err != nil {
		t.Fatalf("OpenRecord: %v", err)
	}
	if _, _, err := pair.opener.OpenRecord(record); !errors.Is(err, ErrOutOfWindow) {
		t.Fatalf("a replay of an accepted application record answered %v, want ErrOutOfWindow: the application arm's acceptance must spend the rung it opened",
			err)
	}
}

// TestTheHeadPlaintextIsNotBoundByTheFrame is a FILED residual and not a repair, written as a case
// so the complement aadMls prints is measured rather than asserted.
//
// ct_head is sealed under the same record_key every member derives and no field of the inner frame
// covers what it says, so a member can take another member's GENUINE body -- frame, signature and
// all -- and re-issue it at the SAME position under a head of its own. R1 passes because the frame
// really is that member's; R2 passes because the position really is that record's.
//
// WHY IT IS FILED RATHER THAN FIXED is in aadMls's own complement: aad_mls is MASTER section 8.4.2's
// construction and a second field in it is a wire change and a spec edit. Open item MG-6.
//
// THIS CASE GOES RED IF SOMEBODY BINDS IT, and that is the intended way for it to end: a build whose
// frame covered the head would refuse the substitute, this case would fail, and the person holding
// the failure would be the person who closed MG-6.
func TestTheHeadPlaintextIsNotBoundByTheFrame(t *testing.T) {
	pair := newTestPair(t, "head-not-bound")
	pair.trackDurable(t)

	plaintext := []byte("the body the sender really wrote")
	genuine, err := pair.sender.SealRecord(message.RetentionDurable, 0, false,
		[]byte("the head the sender wrote"), plaintext, 0, nil)
	if err != nil {
		t.Fatalf("SealRecord: %v", err)
	}
	// the attacker lifts the genuine frame out of the genuine record. The record key is
	// RecordKeyZero(class_key, leaf) walked to this index, and the class key is group shared.
	frame := repairLiftFrame(t, pair.opener, pair.senderLeaf, genuine)
	substituted := []byte("A HEAD THE ATTACKER CHOSE")
	substitute := repairForgeRecord(t, pair.opener, pair.senderLeaf,
		genuine.Header.StreamIndex, substituted, frame)

	head, body, err := pair.opener.OpenRecord(substitute)
	if err != nil {
		t.Fatalf("MG-6 IS CLOSED AND THIS CASE IS THE RECORD OF IT BEING OPEN: the substitute was refused with %v. Delete this case, take the head plaintext out of aadMls's complement, and close MG-6",
			err)
	}
	if !bytes.Equal(head, substituted) || !bytes.Equal(body, plaintext) {
		t.Fatalf("the substitute opened to head %q body %q, want head %q body %q",
			head, body, substituted, plaintext)
	}
	t.Logf("RESIDUAL OPEN (MG-6): a record another member built opened with head=%q body=%q at the true sender's own handle and stream index",
		head, body)
	// and the second half of the cost: the substitute was ACCEPTED, so it spent the rung, and the
	// sender's own record at that index is gone.
	if _, _, err := pair.opener.OpenRecord(genuine); !errors.Is(err, ErrOutOfWindow) {
		t.Fatalf("the sender's own record answered %v after the substitute was accepted at its index, want ErrOutOfWindow",
			err)
	}
}
