// The inner MLS frame an application record's ct_body carries, its aad, and the two refusals an
// opener owes. MASTER section 8.4, RULED 2026-09-15.
//
// WHAT THIS FILE IS, IN ONE SENTENCE. MASTER section 8's record block has read "ct_body ... the
// MLS PrivateMessage payload" since revision 4 and its I5 paragraph "Sender authentication is
// MLS's, inside the ciphertext" for as long; this package padded the application plaintext and
// sealed it under a record key, using MLS as a key schedule and skipping the part of MLS that
// authenticates senders. Neither sentence changes. This file is the build catching up to them.
//
// WHY IT HAD TO. record_key[0] = HKDF-Expand(class_key, "sender/v1" | LP(leaf_index), 32) takes
// the class key EVERY MEMBER HOLDS and a LEAF NUMBER, and a leaf number is an input rather than a
// credential. sender_handle is the same shape and write_auth is a mac under a group wide key. So
// before this file, any member could derive any other member's record key at any position and
// seal a record the whole group opened as that member's -- which was not a defect in any one
// derivation but a property of the whole layer, because every input to it is group shared by
// construction. The signature inside a PrivateMessage is the one secret in the system that is
// not. TestOneMemberCannotForgeAMessageFromAnother is that sentence as a case.
//
// THE SCOPE IS THE BODY AND ONLY THE BODY. No wire field is added, removed, widened or
// reordered; format_version stays 0x02; octet_length(ct_body) is identical at every rung, because
// the rung is what is sealed and the frame sits INSIDE it; AAD_head, AAD_body and the write_auth
// preimage are byte for byte what they were. What changed is the plaintext inside one AEAD the
// server cannot read. The outer AEAD goes on answering the server -- which class, which window,
// which position, may this be erased -- and the inner frame answers members: who wrote this, and
// where.
//
// WHICH RECORDS CARRY ONE IS DERIVED AND NEVER PASSED IN. MASTER section 8.4.1's table is three
// rows and isApplicationRecord below is all three of them:
//
//	is_commit  attachment   inner
//	-----------------------------------------------------------------------------------
//	    1      any          the MLS COMMIT this record announces. It was ALREADY an
//	                        MLSMessage, which is why nobody caught the divergence by reading.
//	    0      NONE         an MLS APPLICATION message from Protect. THE WHOLE CHANGE.
//	    0      anything     no MLS frame at all -- a wrap, an epoch fan out, a completion
//	                        marker. Spec A section 5.11 (5) already said so.
//
// WHAT IT COSTS, MEASURED ON THIS TREE rather than taken from the ruling. A two member group, a
// thirty two octet group id, ciphersuite C5, aad_mls at thirty two octets: the frame's overhead
// over the application plaintext is a STEP FUNCTION, because RFC 9420's varint widens at 64 and
// at 16,384 -- 193 octets for P < 64, 194 for 64 <= P < 16,384 and 198 for P >= 16,384. The
// usable application body per rung falls from 252/1,020/4,092/16,380/65,532 to
// 59/826/3,898/16,186/65,334. mlsframe_test.go publishes that ladder as a case and the query
// beside it, so the numbers in this comment are re-measured rather than re-asserted.
//
// THE 256 OCTET RUNG IS WHERE THE WHOLE BILL LANDS: 252 usable octets become 59, so a text
// longer than about 59 ASCII characters now pays the 1 KiB rung -- 1,040 stored octets where it
// paid 272, 3.8x, for a large fraction of real traffic. That is the price of the digest being 32
// octets rather than 104: carried VERBATIM, AAD_body's 104 octets leave the 256 rung carrying NO
// APPLICATION BODY AT ALL, not even a zero length one, which mlsframe_test.go measures rather
// than asserts. A rung that carries nothing turns every reaction into a 1 KiB record.
//
// AND THE ONE THING THAT STOPS WORKING, which is not in MASTER section 8.4 and is not a cost of
// the digest: A MEMBER CAN NO LONGER OPEN ITS OWN APPLICATION RECORD. Protect consumes a
// generation of this leaf's own sending ratchet, and mls has no receiving ratchet for a leaf's
// own messages, so Unprotect of one's own frame answers "mls: ratchet generation already
// consumed". That is inherent to MLS rather than to this file -- a sender renders its own message
// from the copy it kept, never by decrypting the record -- but it is a real change to what
// OpenRecord does, spec A section 5.2's "it does not make a working call stop working" is false
// of it, and this package's fixtures had to move from one member to two to say so. Open item MG-4.
package messagegroup

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/mls/syntax"
)

// The domain separation label of the inner frame's aad. Raw ascii, never length prefixed, which
// is every other label in this package's shape.
const aadMlsLabel = "URmessage/v1/aad/mls"

// aadMls is MASTER section 8.4.2's authenticated_data: H("URmessage/v1/aad/mls" | AAD_body).
//
// IT IS AAD_body AND NOT A NEW PREIMAGE, and that is the decision this function embodies.
// AAD_body already carries exactly the six fields that fix a record's identity and its position
// -- group_id, sender_handle, epoch, stream_index, the retention wire byte and eph_window -- so
// there is nothing a new preimage would add, one builder cannot drift from itself, and a field
// added to AAD_body later is bound here with no second edit for somebody to forget. It goes
// through message.AADBody and a BodyBinding rather than assembling the six fields again, which is
// guardrail G4 arriving here for free: a value with no hash within its reach cannot put
// body_hash inside the frame that body_hash is a hash of.
//
// IT IS HASHED AND NOT CARRIED VERBATIM, and the reason is a measurement rather than a taste.
// AAD_body is 104 octets, the frame sits inside the size rung, and those octets come out of the
// application body: verbatim, the 256 octet rung carries nothing at all. The digest costs 73
// octets a record against the verbatim column and buys the rung back.
//
// WHAT IT DEFENDS is re-enveloping. A member who cannot forge Alice's signature can still take a
// frame Alice signed and seal it into a DIFFERENT record: a different stream_index, which is a
// replay into a later conversational position and is indistinguishable from Alice saying it
// again, or a different retention_class, which is a DURABLE message dropped into EPH(1) so it
// self-destructs within the hour or an EPH one promoted to PERMANENT so it never does. Both
// attack what the product promises rather than what the ciphertext says, and both are a record
// whose inner aad names a position it is not in.
//
// WHAT IT CANNOT DEFEND, stated here because the complement is the part a reader has to be told.
// AAD_head is NOT bound and CANNOT be in either form: AAD_head contains body_hash = H(ct_body),
// and ct_body is sealed over the frame this aad is inside. That is MASTER section 8's
// construction order seen from the inside. The five fields AAD_head carries and AAD_body does not
// -- is_commit, size_bucket, expire_at, blob_id, H(server_attachment) -- are therefore still
// authenticated by the group alone, and is_commit is the one the SERVER acts on. Ledger open
// item 199.
//
// IT TAKES NO alg_id, and that is this package's own gate rather than a simplification.
// TestEveryAadCallInEitherHalfPassesTheRecordAeadAlgId requires every AADBody call in either half
// of the record layer to pass RecordAeadAlgId itself, on the argument that a literal, an X-Wing
// identifier or an attachment identifier is an aad no second implementation reconstructs. A
// parameter here would have put the one call this file makes outside that rule.
func aadMls(binding message.BodyBinding) ([32]byte, error) {
	aadBody, err := message.AADBody(RecordAeadAlgId, binding)
	if err != nil {
		return [32]byte{}, err
	}
	writer := syntax.NewWriter()
	writer.WriteRaw([]byte(aadMlsLabel))
	writer.WriteRaw(aadBody)
	preimage, err := writer.Bytes()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(preimage), nil
}

// isApplicationRecord is MASTER section 8.4.1's predicate, computed in ONE place and read
// identically by the sealer and by the opener.
//
// It takes the ENCODED attachment rather than the *message.ServerAttachment the sealer holds,
// which is what makes the two sides the same sentence rather than two sentences that agree
// today. connect/message's encoder already collapses a nil attachment and an explicit
// AttachmentNone to NO BYTES AT ALL -- it has to, because MASTER section 8 requires the two to
// contribute the same LP(H(server_attachment)) -- and it already refuses an attachment whose tag
// and whose body disagree. So "the attachment is NONE" is "the encoding is empty", the opener
// reads that off a header field AAD_head has already authenticated, and neither side needs a
// second reading of the presence rule.
func isApplicationRecord(isCommit bool, serverAttachment []byte) bool {
	return !isCommit && len(serverAttachment) == 0
}

// frameBodyOnLoop answers the octets ct_body is sealed over: the inner MLS frame for an
// application record, and the caller's own body for every other kind.
//
// THE ORDER IS FORCED AND IS NOT A PREFERENCE. aad_mls is a digest of AAD_body and AAD_body
// carries stream_index, so there is no legal ordering in which the frame is built before the
// index is reserved. That is why this runs inside newRecordBuilderOnLoop, after Next, rather than
// in front of it where a reader's instinct puts it.
//
// A SECOND WRITE-ONCE RESOURCE IS CONSUMED HERE. Protect takes a generation of this leaf's MLS
// ratchet and persists group state whether or not the record is ever submitted, exactly as the
// reservation takes an index whether or not it is. A refused submit therefore leaves a legal gap
// in TWO sequences. Both are monotonic and both tolerate gaps; the bound is ledger open item 201
// and mls's MaxGenerationSkip is 1,024.
//
// The caller is the loop goroutine, which is what lets it touch self.handle at all.
func (self *GroupSession) frameBodyOnLoop(isCommit bool, serverAttachment []byte,
	binding message.BodyBinding, bodyPlain []byte) ([]byte, error) {

	if !isApplicationRecord(isCommit, serverAttachment) {
		return bodyPlain, nil
	}
	aad, err := aadMls(binding)
	if err != nil {
		return nil, err
	}
	inner, err := self.handle.Protect(aad[:], bodyPlain)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecordInnerFrame, err)
	}
	return inner, nil
}

// refuseFrameBindingsOnLoop is MASTER section 8.4.3's two refusals over one reading of a frame's
// sender leaf and its aad, written once and taken twice.
//
// NEITHER REFUSAL IMPLIES THE OTHER, and the whole reason both are written is that each is
// invisible from the other's side.
//
// R1, the SENDER binding, is what converts "someone in this group" into "Alice". R2 does not
// imply it: a member at leaf B can perfectly well call Protect with an aad_mls naming leaf A's
// handle -- R2 passes, the signature is B's, and the record then claims A while the frame says B.
// An opener without R1 has two answers to "who wrote this" and no rule for choosing, which is a
// forgery with extra steps.
//
// R2, the POSITION binding, is what makes the aad load-bearing rather than decorative, and R1
// does not imply it: R1 pins the writer and says nothing at all about the position, the class or
// the window the writer's frame was put into.
//
// BOTH REFUSE THE WHOLE RECORD. A record failing either is not rendered as a message from
// anybody -- not as a gap attributed to a sender, and not as spec A section 7.4's "malformed",
// which is a different condition about a body that opened.
//
// The caller is the loop goroutine.
func (self *GroupSession) refuseFrameBindingsOnLoop(header *message.RecordHeader,
	position [32]byte, senderLeaf uint32, aad []byte) error {

	// R1. The comparison goes through subtle for guardrail G8's reason and not because a
	// handle is secret: G8 bans the other spelling in a FILE rather than in a kind of
	// function, so every comparison of octets in this package goes one way.
	signed := SenderHandle(self.groupHandleKey, senderLeaf)
	if subtle.ConstantTimeCompare(signed[:], header.SenderHandle[:]) != 1 {
		return fmt.Errorf("%w: the frame was signed at leaf %d, whose handle is %x, and the record carries %x",
			ErrRecordSenderBinding, senderLeaf, signed, header.SenderHandle)
	}
	// R2, against the aad this record's OWN position produces.
	if subtle.ConstantTimeCompare(position[:], aad) != 1 {
		return fmt.Errorf("%w: the frame carries %x and this record's position is %x",
			ErrRecordPositionBinding, aad, position)
	}
	return nil
}

// unframeBodyOnLoop opens the inner frame and takes MASTER section 8.4.3's two refusals.
//
// THE TWO REFUSALS ARE TAKEN TWICE AND THAT IS THE POINT OF THIS FUNCTION'S SHAPE. Once on the
// frame's PRE-RATCHET reading -- peekInnerFrameSender, which opens only the sender data and reads
// the cleartext aad, and which moves nothing -- and once on the values Unprotect has authenticated.
// Only the second decides anything. The first exists because of what sits between them:
//
//	mls opens the frame, verifies the signature, and ERASES the message key of the generation
//	the frame came at. A refusal taken after that has already cost the frame's true sender its
//	own message.
//
// Measured on this tree rather than argued: with the pre-reading removed, a member lifts another
// member's genuine frame out of a record -- the record key is RecordKeyZero(class_key, leaf) and
// the class key is group shared, so every member can -- seals it into a record at a different
// stream_index, and the opener refuses it at R2 AFTER mls has erased the generation. The true
// sender's own record at that generation then answers "mls: ratchet generation already consumed"
// at that receiver forever. One ordinary record, at the attacker's own handle and its own index,
// per message the attacker wants deleted, chosen precisely.
// TestARecordRefusedAtTheInnerFrameMovesNoReceiverRatchet drives both refusals and is red without
// the pre-reading.
//
// WHY A PRE-READING IS NOT A WEAKER SECOND RULE. The two values it reads are the two values the
// signature covers: the leaf is the one mls builds its Sender from, and the aad is the cleartext
// authenticated_data the content AEAD is taken over, so a message that OPENS cannot disagree with
// its own peek -- mls's TestThePeekAgreesWithTheOpenOnEveryMessageThatOpens is that, swept over
// every boundary generation. The peek can therefore only ever refuse what the second reading would
// have refused, and the second reading is still written, still reached and still the answer.
//
// AND BOTH RUN BEFORE THE RECEIVER RATCHET COMMITS, which is openRecordOnLoop's own discipline
// one level out. A forged envelope at the true sender's next index would otherwise burn that index
// at every opener, so a refusal that moved that ladder would turn a forgery this file defeats into
// a denial it causes. That is the same sentence as the paragraph above, about the other of the two
// receiver ratchets a record passes through.
//
// The caller is the loop goroutine.
func (self *GroupSession) unframeBodyOnLoop(header *message.RecordHeader,
	bodyPlain []byte) ([]byte, error) {

	if !isApplicationRecord(header.IsCommit, header.ServerAttachment) {
		return bodyPlain, nil
	}
	// the aad this record's position produces, built from the same BodyBinding the sealer used
	// and by the same function. It is computed once and handed to both readings, so the early
	// refusal and the deciding one cannot come to disagree about where this record is.
	position, err := aadMls(header.BodyBinding())
	if err != nil {
		return nil, err
	}
	peekLeaf, peekAad, err := peekInnerFrameSender(self.handle, bodyPlain)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecordInnerFrame, err)
	}
	if err := self.refuseFrameBindingsOnLoop(header, position, peekLeaf, peekAad); err != nil {
		return nil, err
	}
	aad, plaintext, senderLeaf, err := self.handle.Unprotect(bodyPlain)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecordInnerFrame, err)
	}
	// and again, on what the signature covers. This is the reading that decides.
	if err := self.refuseFrameBindingsOnLoop(header, position, senderLeaf, aad); err != nil {
		return nil, err
	}
	return plaintext, nil
}
