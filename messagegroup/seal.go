// SealRecord and OpenRecord: spec A section 5.2's two methods, and the body padder that no
// document specifies.
//
// SECTION 5.2's TITLE IS "Construction order is a type, not a convention", and this file takes
// that literally rather than as an instruction to comment carefully. MASTER section 8 fixes the
// order:
//
//	build server_attachment -> encrypt ct_body -> compute body_hash -> encrypt ct_head ->
//	compute write_auth. Every dependency is acyclic, and getting it wrong produces a circular
//	AAD that appears to work until two implementations disagree.
//
// The staging types below are that order. recordBuilder is what exists once the attachment is
// encoded and the stream index is reserved; the only thing it can do is seal the body, and what
// that answers is a recordBodySealed; the only thing THAT can do is bind body_hash; and so on to
// the record. A body that sealed the head first cannot be written, because the value it would
// need does not exist yet -- which is the difference between a rule and a type, and it is the
// same move connect/mls made when it turned its proposal buckets into derived accessors so that
// divergence became unrepresentable.
//
// THE SCOPE OF THAT SENTENCE, because the unqualified version of it was false where it mattered.
// The staging types are unexported, so no other package can build one at all and the order is a
// TYPE across the package boundary. INSIDE this package a keyed composite literal of any of them
// is legal go, and the stages used to be wrappers over one shared message.RecordHeader that
// bindBodyHash mutated as a side effect -- so a member of this package could assemble a
// recordBodyBound with no hash in it, seal the head first, and get a record message.EncodeRecord
// accepted with body_hash all zero. That was measured rather than imagined, and tasks 13 to 16 are
// the next members of this package.
//
// Two repairs, both below. Each stage now CARRIES the value the next one needs rather than
// reaching for it through a shared pointer, so bindBodyHash is a pure function of the ct_body and
// sealHead is the only writer of header.BodyHash; and sealHead refuses a stage whose carried hash
// is not the hash of the ct_body it wraps, with ErrRecordStageOrder, which is what a skipped stage
// now costs. The cost is one sha256 over a rung sized buffer per record, which is the same hash
// the open path already pays. engine.go states the same kind of scope distinction for
// EngineProcessed.stagedRef, and this file states it rather than claiming the stronger thing.
//
// The four functions the order runs through already carry it in their SIGNATURES, and this file
// derives nothing: AADBody takes a BodyBinding with no hash within reach, which is guardrail G4
// built as a signature; AADHead reads body_hash off the header; WriteAuthPreimage takes
// H(ct_head); ComputeWriteAuth closes it.
//
// THREE DECISIONS THIS FILE TAKES, AND SAYS IT IS TAKING.
//
// (a) WHICH record_key SEALS THE HEAD -- RULED 2026-09-13, AND THE BLANKET CLASS REFUSAL THIS
// FILE CARRIED IS LIFTED IN FULL. ct_head is keyed under the RECORD'S OWN class key, whatever
// that class is, exactly as ct_body is: head and body take ONE ladder at ONE position, separated
// only by their HKDF labels "rec/v1/head" and "rec/v1/body" (MASTER I7). Ledger items 152 and
// 128, spec A revision A-25, and it REVERSES the ruling of 2026-09-07.
//
// WHAT THIS FILE USED TO SAY, because a reversal that erases what it reverses leaves the next
// reader unable to reconstruct it. It said: "MASTER section 8.1 says ct_head is always under the
// durable class and section 5.3 hands both aead derivations one record_key[i] ... Open item M1-6
// rules it. Until then a class other than DURABLE is REFUSED, with a sentinel naming the item."
// M1-6 was ruled on 2026-09-07 and that sentence was stale from that day; on 2026-09-13 the
// ruling itself was reversed. Its premise -- "the head is always retained, so it is keyed by the
// class that is always retained" -- is false for exactly one class and it is the class the whole
// question was about: spec B section 7.2 sets ct_head = NULL for EPH(1..5) at prune_after, so an
// EPH head is not always retained. Spec A section 5.3: "THE REFUSAL IS NOW LIFTED IN FULL ...
// SealRecord and OpenRecord may seal and open EVERY retention class."
//
// WHAT REPLACES IT IS NOT NOTHING, and the two replacements are refusals about VALUES rather
// than about classes. A session that holds no eph_root cannot derive K_eph at all and refuses
// with ErrNoEphRoot. And the eph_root DEVICE WRAP is refused outright with
// ErrEphWrapWindowUnruled -- ledger open item 185, spec A section 5.11: "A builder MUST NOT
// PUBLISH THAT RECORD UNTIL IT IS [ruled]". That refusal REPLACES the lifted one for exactly one
// record and is not a survival of it.
//
// (b) HOW THE BODY IS PADDED, and how the reader recovers its length. Section 5.1 fixes
// octet_length(ct_body) at size_bucket_bytes[b] + 16 exactly, so the plaintext is padded to
// SizeBucketBytes(b) before the aead. NO DOCUMENT STATES THE SCHEME -- pad.go is named in
// section 2.2's tree with no section anywhere, and msgrepo's harness pads with byte(index*31)
// and never unpads because it never reads a body back. Open item M1-7, wire visible, blocks the
// A6 freeze. Pending the ruling the padder and the unpadder are ONE unexported pair here, so the
// ruling is one edit, and OpenRecord's round trip is what binds them.
//
// (c) THE EMPTY ATTACHMENT. Section 5.2 says serverAttachment is nil for an ordinary record and
// MUST then encode zero length; section 5.11 says a parser MUST refuse an ENCODED kind 0x0000.
// Neither says what SealRecord does with a non-nil &ServerAttachment{Kind: AttachmentNone}, which
// is what a caller building attachments in a loop naturally produces. attachment.go already chose
// the safe reading and documented it -- a nil attachment and an AttachmentNone attachment both
// answer no bytes at all -- so this file CALLS EncodeServerAttachment and uses its answer rather
// than adding a second nil check. Open item M1-18.
package messagegroup

import (
	"crypto/sha256"
	"crypto/subtle"

	"fmt"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/mls/syntax"
)

// SealRecord builds one record: the attachment, the body, its hash, the head, and the mac, in
// that order and in no other.
//
// It runs on the session's loop goroutine, like every other method that touches session state.
//
// EVERY RETENTION CLASS IS SEALED. See decision (a) at the top of this file: the blanket refusal
// of every class but DURABLE was lifted in full on 2026-09-13 when ledger item 152 was ruled and
// ct_head became the record's own class key's. What is still refused is the eph_root device
// wrap, whose own eph_window value is ledger open item 185 and is not ruled, and an EPH record of
// any bucket when this session holds no eph_root to derive K_eph from.
//
// THE EPH WINDOW IS READ OFF THIS SESSION'S CLOCK EXACTLY ONCE, HERE, ON THE SEAL PATH ONLY.
// MASTER section 8.1 makes eph_window the SENDER's computation from the same wall clock reading
// it puts in sent_at; sent_at lives inside headPlain, which is opaque to this layer, so the one
// thing this layer can do is take one reading from the injected nowMs and use it for the window.
// A CALLER THAT BUILDS headPlain WITH A sent_at FROM A DIFFERENT READING can straddle a bucket
// boundary between the two, in which case the record is still perfectly self consistent -- the
// window is on the wire, in both AADs and in write_auth, and the key is derived from the wire
// value -- but its key lifetime is pinned to this reading rather than to the sent_at inside it.
// Section 5.2 fixes this signature with no sent_at parameter in it, so closing that gap is a
// signature change to a published block rather than something this file may do; it is recorded
// here and in this package's OPENITEMS.md rather than papered over.
func (self *GroupSession) SealRecord(class message.RetentionClass, ephBucket uint8, isCommit bool,
	headPlain []byte, bodyPlain []byte, expireAt uint64,
	serverAttachment *message.ServerAttachment) (*message.Record, error) {

	var record *message.Record
	var err error
	if postErr := self.do(func() {
		if self.closing {
			err = ErrSessionClosed
			return
		}
		record, err = self.sealRecordOnLoop(class, ephBucket, isCommit, headPlain, bodyPlain,
			expireAt, serverAttachment)
	}); postErr != nil {
		return nil, postErr
	}
	if err != nil {
		return nil, err
	}
	return record, nil
}

// sealRecordOnLoop is SealRecord's body. The caller is the loop goroutine.
//
// THE ORDER IS THE CHAIN OF STAGING TYPES AND NOT THE ORDER OF THESE STATEMENTS. Each stage
// answers the value the next one is a method on, so the sequence below is the only sequence that
// compiles.
func (self *GroupSession) sealRecordOnLoop(class message.RetentionClass, ephBucket uint8,
	isCommit bool, headPlain []byte, bodyPlain []byte, expireAt uint64,
	serverAttachment *message.ServerAttachment) (*message.Record, error) {

	// ONE CLOCK READING PER RECORD, taken here and used for both things this body asks the
	// time for. Two readings would let expire_at be judged against one instant and the window
	// computed from another, which is a record that can be refused as expired in a window it
	// was never in.
	nowMs := self.nowMs()
	if expireAt != 0 && expireAt <= uint64(nowMs) {
		return nil, fmt.Errorf("%w: expire_at %d is not after now", ErrRecordExpired, expireAt)
	}
	ephWindow, err := self.sealEphWindowOnLoop(class, ephBucket, nowMs, serverAttachment)
	if err != nil {
		return nil, err
	}
	builder, err := self.newRecordBuilderOnLoop(class, ephBucket, ephWindow, isCommit, len(bodyPlain), expireAt, serverAttachment)
	if err != nil {
		return nil, err
	}
	defer builder.zeroize()
	bodySealed, err := builder.sealBody(bodyPlain)
	if err != nil {
		return nil, err
	}
	bodyBound := bodySealed.bindBodyHash()
	headSealed, err := bodyBound.sealHead(headPlain)
	if err != nil {
		return nil, err
	}
	return headSealed.authenticate()
}

// sealEphWindowOnLoop answers this record's eph_window, and refuses the one record whose value
// is not ruled.
//
// MASTER SECTION 8'S PRESENCE RULE, AS AN ANSWER RATHER THAN AS A BRANCH SOMEWHERE ELSE. The
// field is ALWAYS present and its VALUE carries the absence: zero on PERMANENT, DURABLE, MEDIA
// and EPH(0), the bucket's own window on EPH(1..5). Every one of those four zeros comes out of
// this one function, so no preimage builder and no codec half gains a conditional for the rule
// -- which is the whole reason the rule is a zero VALUE and not a zero LENGTH.
//
// EPH(0) IS A ZERO THAT IS COMPUTED AND NOT A CLASS THAT IS SKIPPED. EphWindowAt answers 0 for
// bucket 0 without dividing, because master section 8.1 makes t = 0 "BY DEFINITION" there -- the
// transient rung is never persisted, so it has one window for the life of eph_root[n]. That
// arrives here through the ladder's own answer rather than through a bucket == 0 test, which is
// what keeps this function and message.EphBucketSeconds from drifting.
//
// THE eph_root DEVICE WRAP IS REFUSED, AND THE REFUSAL REPLACES THE LIFTED ONE RATHER THAN
// SURVIVING IT. Ledger open item 185, filed 2026-09-13 (second pass of that date) and not ruled;
// spec A section 5.11 states it as an instruction to a builder rather than as a note: "AND THE
// eph_root WRAP'S OWN eph_window VALUE IS NOT RULED. A builder MUST NOT PUBLISH THAT RECORD
// UNTIL IT IS." Three landed sentences cannot all be satisfied by it -- the presence rule makes
// the field non zero on EPH(1..5) and that record is EPH(5); requirement S19 and spec B section
// 5.1 check 3 refuse an implausible window with no carve out for a wrap anywhere; and the
// formula divides sent_at, which a wrap head does not have because a wrap carries no MLS frame
// (section 5.11 part 5). So this function does not pick whichever value compiles. It refuses.
//
// WHAT THE REFUSAL IS KEYED ON, and it is derived from what makes that record that record rather
// than from a flag a caller passes. An eph_root device wrap is, by spec A section 5.11's own
// table, an EPH class record carrying a WrapTag server attachment; the pq_secret device wrap is
// the same attachment on a PERMANENT record and is UNAFFECTED, because PERMANENT carries the
// presence rule's zero and item 185 is about a value only an EPH record has to have. The
// attachment is read through the same presence rule connect/message computes rather than through
// the Kind tag alone, so an attachment whose tag and whose body disagree is caught here as well
// as at the encoder.
//
// The caller is the loop goroutine.
func (self *GroupSession) sealEphWindowOnLoop(class message.RetentionClass, ephBucket uint8,
	nowMs int64, serverAttachment *message.ServerAttachment) (uint64, error) {

	if class != message.RetentionEph {
		// the presence rule's three non-eph zeros. The value is computed by the same
		// sentence that computes the other three rather than returned early with a
		// literal somewhere else.
		return 0, nil
	}
	if isEphRootDeviceWrap(serverAttachment) {
		return 0, fmt.Errorf("%w: this record is EPH bucket %d and carries a wrap tag", ErrEphWrapWindowUnruled, ephBucket)
	}
	window, err := EphWindowAt(ephBucket, nowMs)
	if err != nil {
		return 0, err
	}
	return window, nil
}

// ephLadderWindow is the window that ROOTS a record's ladder, which is not always the window the
// record carries.
//
// The rule is one sentence and it is about class keys rather than about fields: a ladder is
// rooted at record_key[0] = HKDF-Expand(class_key, ...), and only the EPH class key is a function
// of the window -- K_eph[n][b][t] takes t, while K_perm, K_durable and K_media take none. So for
// every other class the answer is zero however the field reads, and the ladder tables collapse to
// what they were before the field existed.
//
// THE ONLY INPUT THIS CHANGES IS A LYING ONE. MASTER section 8's presence rule makes eph_window
// zero on every non-EPH record, so a well formed record answers the same either way; what it
// decides is where a TAMPERED one fails. With this, it fails in the AEAD, which is what binds the
// field -- it is in both aads for exactly that reason. Without it, it would miss the ratchet
// table and be refused as an untracked sender, which reports the wrong thing about the wrong
// field.
func ephLadderWindow(class message.RetentionClass, ephWindow uint64) uint64 {
	if class == message.RetentionEph {
		return ephWindow
	}
	return 0
}

// isEphRootDeviceWrap says whether an attachment makes its record a device wrap.
//
// It asks BOTH halves of connect/message's own presence rule -- the declared tag and the body
// that is actually set -- because this refusal runs before EncodeServerAttachment is called and
// is therefore in front of the check that makes the two agree. An attachment that carried a
// WrapTag body under some other tag would otherwise walk past item 185's refusal and be caught
// two calls later as a tag mismatch, which is a different sentence about a different problem.
func isEphRootDeviceWrap(serverAttachment *message.ServerAttachment) bool {
	if serverAttachment == nil {
		return false
	}
	return serverAttachment.Kind == message.AttachmentWrap || serverAttachment.Wrap != nil
}

// recordBuilder is the first stage: the header as far as it can be filled before anything is
// sealed, the encoded attachment, and the rung of the ladder this record is sealed under.
//
// It is unexported and it is never returned by anything exported, so the only way to reach a
// later stage is to go through the earlier one.
type recordBuilder struct {
	session   *GroupSession
	header    message.RecordHeader
	recordKey []byte
	bucket    message.SizeBucket
}

// newRecordBuilderOnLoop reserves the stream index and stages the header.
//
// THE RESERVATION IS FIRST AND IS THE WHOLE POINT OF THIS FUNCTION EXISTING. Section 5.6 requires
// a device to record "index k consumed" durably BEFORE encrypting, and SenderRatchet.Next is
// where that ordering is made; every path from SealRecord to a record aead derivation runs
// through here, and seal_test.go walks the call graph to say so rather than trusting this
// sentence.
func (self *GroupSession) newRecordBuilderOnLoop(class message.RetentionClass, ephBucket uint8,
	ephWindow uint64, isCommit bool, bodyLength int, expireAt uint64,
	serverAttachment *message.ServerAttachment) (*recordBuilder, error) {

	// (c): the encoder's answer and not a second nil check. A nil attachment and an
	// AttachmentNone attachment both answer no bytes, so both contribute the same
	// LP(H(server_attachment)).
	attachmentBytes, err := message.EncodeServerAttachment(serverAttachment)
	if err != nil {
		return nil, err
	}
	retentionWire, err := message.RetentionClassWire(class, ephBucket)
	if err != nil {
		return nil, err
	}
	bucket, err := bucketForBody(bodyLength)
	if err != nil {
		return nil, err
	}
	ratchet, err := self.senderRatchetOnLoop(class, retentionWire, ephBucket, ephWindow)
	if err != nil {
		return nil, err
	}
	streamIndex, recordKey, err := ratchet.Next()
	if err != nil {
		return nil, err
	}
	return &recordBuilder{
		session:   self,
		recordKey: recordKey,
		bucket:    bucket,
		header: message.RecordHeader{
			GroupId:        self.groupId,
			SenderHandle:   self.senderHandle,
			Epoch:          self.epoch,
			StreamIndex:    streamIndex,
			IsCommit:       isCommit,
			RetentionClass: class,
			EphBucket:      ephBucket,
			// MASTER section 8's presence rule, carried as a VALUE the caller of this
			// function computed rather than as a zero this one writes.
			//
			// It was literally "EphWindow: 0" until the seal refusal lifted, with a
			// comment saying that the day eph became sealable this line was the one that
			// had to take a computed window. That day was 2026-09-13 and this is that
			// line. sealEphWindowOnLoop answers zero on PERMANENT, DURABLE, MEDIA and
			// EPH(0) -- the presence rule's four zero cases -- and the bucket's own
			// window on EPH(1..5), so the presence rule is still stated by a value and
			// still by no branch in any preimage builder.
			EphWindow:        ephWindow,
			SizeBucket:       bucket,
			ExpireAt:         expireAt,
			ServerAttachment: attachmentBytes,
		},
	}, nil
}

// zeroize erases the rung this builder was handed. The caller owns what Next gave it and owes it
// this erasure; a deferred call is how that obligation is met on every exit including the
// refusals.
//
//go:noinline
func (self *recordBuilder) zeroize() {
	zeroize(self.recordKey)
}

// sealBody pads the plaintext into its rung and seals it under record_key's body half.
//
// The aad is built from a BodyBinding, which is guardrail G4: the builder AADBody is handed has
// no hash within its reach, so body_hash cannot be put in aad_body by any edit to this line.
func (self *recordBuilder) sealBody(bodyPlain []byte) (*recordBodySealed, error) {
	padded, err := padBody(self.bucket, bodyPlain)
	if err != nil {
		return nil, err
	}
	aadBody, err := message.AADBody(RecordAeadAlgId, self.header.BodyBinding())
	if err != nil {
		return nil, err
	}
	key, nonce := RecordAeadBody(self.recordKey)
	defer zeroize(key)
	defer zeroize(nonce)
	ctBody, err := sealRecordAead(key, nonce, aadBody, padded)
	if err != nil {
		return nil, err
	}
	return &recordBodySealed{builder: self, ctBody: ctBody}, nil
}

// recordBodySealed is the second stage: the body is ciphertext and its hash has not been taken.
type recordBodySealed struct {
	builder *recordBuilder
	ctBody  []byte
}

// bindBodyHash takes H(ct_body) and hands it to the next stage.
//
// It is SHA-256 OF THE CIPHERTEXT and never of the plaintext, and never of the unpadded
// plaintext: section 5.1 keeps body_hash after ct_body has been pruned, so it is what a pruned
// record still says about what it carried, and a hash of anything else would be a value no
// holder of the record can recompute.
//
// It writes NOTHING. It used to mutate the shared header and answer a stage carrying no value at
// all, which is what made the stage skippable inside this package: the next stage's zero value was
// as good as the real one. The hash travels in the stage now, so the only way to hold a
// recordBodyBound that sealHead accepts is to have run this.
func (self *recordBodySealed) bindBodyHash() *recordBodyBound {
	return &recordBodyBound{sealed: self, bodyHash: sha256.Sum256(self.ctBody)}
}

// recordBodyBound is the third stage: the body's hash exists and nothing of the head does.
type recordBodyBound struct {
	sealed *recordBodySealed
	// H(ct_body), carried rather than written into the shared header, so this stage's zero value
	// is not a usable one.
	bodyHash [32]byte
}

// sealHead seals the head plaintext under record_key's head half.
//
// The aad covers every field of the header, body_hash included, which is what makes the head's
// authentication cover the body it belongs to. The attachment is passed BESIDE the header and
// connect/message refuses a disagreement between the two in both directions, so a call that
// passed nil while the header carried an attachment is a refusal rather than a record nothing
// will ever reproduce.
func (self *recordBodyBound) sealHead(headPlain []byte) (*recordHeadSealed, error) {
	builder := self.sealed.builder
	// THE STAGE IS CHECKED, because inside this package a keyed composite literal can build one
	// with no hash in it. A recordBodyBound whose carried hash is not the hash of the ct_body it
	// wraps is a stage nothing produced, and the answer is a refusal here rather than a record
	// with a zero body_hash that the codec accepts and every reader refuses.
	bound := sha256.Sum256(self.sealed.ctBody)
	if subtle.ConstantTimeCompare(self.bodyHash[:], bound[:]) != 1 {
		return nil, fmt.Errorf("%w: the head cannot be sealed before H(ct_body) is bound", ErrRecordStageOrder)
	}
	// and this is the ONE writer of body_hash, so the field a reader meets in the header is the
	// value the previous stage produced and not one some earlier statement left there.
	builder.header.BodyHash = self.bodyHash
	aadHead, err := message.AADHead(RecordAeadAlgId, &builder.header, builder.header.ServerAttachment)
	if err != nil {
		return nil, err
	}
	key, nonce := RecordAeadHead(builder.recordKey)
	defer zeroize(key)
	defer zeroize(nonce)
	ctHead, err := sealRecordAead(key, nonce, aadHead, headPlain)
	if err != nil {
		return nil, err
	}
	return &recordHeadSealed{bound: self, ctHead: ctHead}, nil
}

// recordHeadSealed is the fourth stage: both ciphertexts exist and the record is not yet
// authenticated.
type recordHeadSealed struct {
	bound  *recordBodyBound
	ctHead []byte
}

// authenticate takes the record's mac and answers the finished record.
//
// It is the last step of the order and there is nothing after it: every input the preimage
// covers already exists, which is what "the dependencies are acyclic" means when it is written
// as a type.
//
// The finished record goes through message.EncodeRecord and the bytes are discarded, so the
// record this function answers is exactly the record the codec accepts -- Property 5's "the
// record EncodeRecord refuses is the record SealRecord refuses", held by calling it rather than
// by reimplementing checkRecord here.
func (self *recordHeadSealed) authenticate() (*message.Record, error) {
	builder := self.bound.sealed.builder
	record := &message.Record{
		Header: builder.header,
		CtHead: self.ctHead,
		CtBody: self.bound.sealed.ctBody,
	}
	record.WriteAuth = message.ComputeWriteAuth(builder.session.writeKey, builder.session.serverNonce,
		&record.Header, record.CtHead, record.Header.ServerAttachment)
	if _, err := message.EncodeRecord(record); err != nil {
		return nil, err
	}
	return record, nil
}

// refuseAheadEphWindowOnLoop is spec A section 5.3's opener rule, and the whole of it is that it
// is ASYMMETRIC.
//
//	An opener MUST refuse an EPH(1..5) record whose eph_window is more than one window AHEAD
//	of its own clock, with a typed error separable by errors.Is from every AEAD failure ... A
//	window behind the opener's own is NOT a refusal in any amount.
//
// WHY AHEAD IS A REFUSAL. The opener can derive ANY window's key from eph_root[n] -- an
// HKDF-Expand takes whatever t it is handed, and EphKey is the evidence for that sentence -- so
// a far future window is not a record the opener cannot read, it is a record the opener CAN read
// and should not: honouring it keeps the record openable long past its timer, for every record a
// hostile sender or a hostile server puts in front of this client, with master section 12.4's
// required user facing string false and nothing anywhere reporting it. The server side check of
// requirement S19 is the only other thing standing there, and a client that trusts the server to
// have made it is a client that has made the server a participant in its own confidentiality.
//
// WHY BEHIND IS NOT. A record from a closed window is a record whose key the opener either still
// holds or has destroyed on schedule; the first opens, the second is a gap with reason expired.
// Neither is this refusal's business, and a refusal that fired on them would refuse the ordinary
// case -- a record that sat in a queue, or arrived over a slow link, or was fetched after an
// offline stretch. There is no lower bound here, in any amount, deliberately.
//
// PLUS ONE AND NOT PLUS TWO. Master section 9.2 fixes the tolerance at one window in either
// direction on the server's side and gives the reason in this field's unit: the sender computes
// from sent_at and the opener sees arrival, which is the skew spec B section 7.1's one hour
// grace already absorbs, while two windows is a doubling of the shortest bucket's guarantee.
//
// EPH(0) IS NOT SUBJECT TO IT. Bucket 0's window is 0 by definition and is never computed from a
// clock, so there is no "own window" to be ahead of; EphWindowAt answers 0 for it and the
// comparison below is 0 against 0. That falls out of the ladder's answer rather than out of a
// bucket == 0 test.
//
// THE ARITHMETIC IS WRITTEN SO IT CANNOT WRAP. window - own is computed only after window > own
// is known, so the u64 subtraction has no negative case and own + 1 is never formed.
//
// The caller is the loop goroutine.
func (self *GroupSession) refuseAheadEphWindowOnLoop(header *message.RecordHeader) error {
	if header.RetentionClass != message.RetentionEph {
		return nil
	}
	own, err := EphWindowAt(header.EphBucket, self.nowMs())
	if err != nil {
		return err
	}
	if own < header.EphWindow && 1 < header.EphWindow-own {
		return fmt.Errorf("%w: the record names window %d, this opener is in window %d, and bucket %d admits one",
			ErrEphWindowAhead, header.EphWindow, own, header.EphBucket)
	}
	return nil
}

// OpenRecord is the only consumer, and it never trusts a field the record's own authentication
// does not cover.
//
// THE TWO FAILURES THAT ARE NOT ERRORS ARE STILL ERRORS HERE, and that is open item M1-15 rather
// than a decision this file takes. Section 5.5 says a record beyond the window "surfaces as a
// Kind == gap entry with GapReason == out_of_window -- NOT as an error", and section 5.11 step 5
// says the same of a missing device wrap. This signature has ONE error channel and section 5.9
// G7 makes every error in this package fatal by construction, so what ships is the pair of
// sentinels sdk matches with errors.Is -- ErrOutOfWindow and ErrNoWrap -- and NOT a third return
// value invented on this plan's own authority.
//
// A PARTIAL PLAINTEXT IS NEVER RETURNED BESIDE AN ERROR. On every refusal both slices are nil: a
// caller that rendered whatever came back would be rendering attacker chosen octets.
func (self *GroupSession) OpenRecord(record *message.Record) ([]byte, []byte, error) {
	var headPlain []byte
	var bodyPlain []byte
	var err error
	if postErr := self.do(func() {
		if self.closing {
			err = ErrSessionClosed
			return
		}
		headPlain, bodyPlain, err = self.openRecordOnLoop(record)
	}); postErr != nil {
		return nil, nil, postErr
	}
	if err != nil {
		return nil, nil, err
	}
	return headPlain, bodyPlain, nil
}

// openRecordOnLoop is OpenRecord's body. The caller is the loop goroutine.
//
// The receiver ratchet is read through its TWO PHASE form. Nothing authenticates a stream index
// before this point -- write_auth is a mac under the group's write key, which spec A hands to the
// server, and aad_head binds stream_index only when the aead opens -- so the peek derives without
// moving the ratchet, and the commit happens only after both ciphertexts have authenticated.
// (*ReceiverRatchet).PeekFor carries the measurement of what the committing form costs when the
// index turns out to be forged.
func (self *GroupSession) openRecordOnLoop(record *message.Record) ([]byte, []byte, error) {
	if record == nil {
		return nil, nil, message.ErrRecordNil
	}
	header := record.Header
	// the group id through subtle and the epoch with ==. Guardrail G8 is a rule about the
	// SPELLING and its class is derived off this tree's own imports, so every comparison of
	// OCTETS goes one way whether or not the octets are secret -- a group id is public and is
	// compared this way because a ban with one exemption in it is a ban with a judgement call in
	// front of it. An epoch is a u64 and not octets, and it is compared as one.
	if subtle.ConstantTimeCompare(header.GroupId[:], self.groupId[:]) != 1 || header.Epoch != self.epoch {
		return nil, nil, fmt.Errorf("%w: group %x epoch %d", ErrRecordNotForThisSession, header.GroupId, header.Epoch)
	}
	if err := self.refuseAheadEphWindowOnLoop(&header); err != nil {
		return nil, nil, err
	}
	if header.SizeBucket == message.SizeBucketBlob {
		return nil, nil, fmt.Errorf("%w: blob %x", ErrBlobRecordUnsupported, header.BlobId)
	}
	retentionWire, err := message.RetentionClassWire(header.RetentionClass, header.EphBucket)
	if err != nil {
		return nil, nil, err
	}
	// body_hash against the ciphertext in hand, BEFORE either aead runs.
	//
	// WHAT IT BUYS IS AN EARLIER AND CHEAPER REFUSAL AND NOT AN AUTHENTICATION, which is worth
	// writing down because the sentence that used to stand here read as the second. Measured:
	// disabling this check survives the whole of ./mls/ ./message/ ./messagegroup/. It has to --
	// a moved ct_body fails the body aead, and a moved body_hash changes aad_head so the HEAD
	// fails, so every input this refuses is one something below would refuse anyway. What it
	// changes is that a record whose two halves disagree costs no peek of the receiver's ladder
	// and no aead at all, and that it is refused by the field that says what the body was rather
	// than by a tag failure that says nothing.
	//
	// It also makes the "no partial plaintext" hazard on the BODY path unreachable rather than
	// merely guarded: with this check in front, no input opens ct_head and then fails ct_body.
	// The guards are still there, and seal_test.go holds them off the source for that reason.
	bodyHash := sha256.Sum256(record.CtBody)
	if subtle.ConstantTimeCompare(bodyHash[:], header.BodyHash[:]) != 1 {
		return nil, nil, fmt.Errorf("%w: the header's body_hash is not the hash of this ct_body", ErrRecordAeadOpen)
	}
	// THE WINDOW IN THE RATCHET KEY IS THE RECORD'S OWN AND NEVER THIS OPENER'S. An EPH
	// ladder is rooted at EphKey(eph_root, bucket, window), so the key that opens this record
	// is the one derived from the value on the wire -- which is what "an opener takes the wire
	// value and never recomputes it" means once it reaches a table lookup. The refusal above is
	// the ONLY thing on this path that consults a clock, and it decides whether to open at all
	// rather than what to open with.
	//
	// IT GOES THROUGH ephLadderWindow AND NOT STRAIGHT OFF THE HEADER, which matters only for
	// a record that is lying. On a non-EPH class the class key is not a function of the window
	// at all, so the ladder is the same ladder whatever the field says; a tampered non-zero
	// window on a DURABLE record must therefore reach the AEAD and fail there, because the
	// window is in BOTH aads and that is the thing being tested. Keying the table on the raw
	// field would have made it miss the ratchet instead and refuse with "no receiver ratchet
	// is tracked", which is a true sentence about the wrong subject.
	ratchetKey := ReceiverRatchetKey{
		SenderHandle:  header.SenderHandle,
		RetentionWire: retentionWire,
		EphWindow:     ephLadderWindow(header.RetentionClass, header.EphWindow),
	}
	recordKey, err := self.receivers.PeekFor(ratchetKey, header.StreamIndex)
	if err != nil {
		return nil, nil, err
	}
	defer zeroize(recordKey)
	aadHead, err := message.AADHead(RecordAeadAlgId, &header, header.ServerAttachment)
	if err != nil {
		return nil, nil, err
	}
	headKey, headNonce := RecordAeadHead(recordKey)
	defer zeroize(headKey)
	defer zeroize(headNonce)
	headPlain, err := openRecordAead(headKey, headNonce, aadHead, record.CtHead)
	if err != nil {
		return nil, nil, err
	}
	aadBody, err := message.AADBody(RecordAeadAlgId, header.BodyBinding())
	if err != nil {
		return nil, nil, err
	}
	bodyKey, bodyNonce := RecordAeadBody(recordKey)
	defer zeroize(bodyKey)
	defer zeroize(bodyNonce)
	padded, err := openRecordAead(bodyKey, bodyNonce, aadBody, record.CtBody)
	if err != nil {
		return nil, nil, err
	}
	bodyPlain, err := unpadBody(header.SizeBucket, padded)
	if err != nil {
		return nil, nil, err
	}
	// and only now does the ratchet move. Everything above authenticated, so the stream index
	// this commit acts on is one a key opened a record at rather than one a header claimed.
	if err := self.receivers.Commit(ratchetKey, header.StreamIndex); err != nil {
		return nil, nil, err
	}
	return headPlain, bodyPlain, nil
}

// ReauthRecord recomputes one already sealed record's write_auth under this session's CURRENT
// write_key and CURRENT server_nonce, and touches nothing else.
//
// WHAT IT IS, IN ONE SENTENCE, BECAUSE THE NAME INVITES A LARGER READING. It is spec A section
// 5.7's "every queued record MUST be re-MAC'd against the new connection's nonce before
// submission", and it is nothing more. Every other input message.ComputeWriteAuth takes is
// already on the record: the header, ct_head and the server attachment. Nothing is re-encrypted,
// no stream index is consumed, no ratchet moves, and RecordId, Header, CtHead and CtBody come
// back byte-identical -- which noncerebind_test.go holds as a property over message.Record's own
// field set rather than over a list, so a sixth field added there next month is in the class with
// no edit here.
//
// WHY IT EXISTS AT ALL is RebindServerNonce's blast radius read from the other end: write_auth is
// the one sealed value the nonce binds, so a rebind leaves every record already in the outbox
// carrying a mac the new connection will refuse, and this is the repair for exactly those.
//
// AND WHAT IT REFUSES, BECAUSE THE SAME SECTION RULES THE NEIGHBOURING CASE DIFFERENTLY. Section
// 5.7's outbox rule has two clauses and they prescribe two different costs: the nonce case is
// re-MAC'd, and the epoch case -- REASON_EPOCH_STALE -- is "discarded and re-sealed at the new
// epoch, consuming a fresh stream_index". A RE-MAC OF A RECORD WHOSE EPOCH HAS PASSED IS
// WELL-FORMED, CHEAP AND WRONG: the tag would be taken under write_key[n+1] over a header naming
// epoch n, which no server verifies and which no round trip in this package would notice, because
// the record agrees with itself perfectly. So it is refused here. The refusal is the whole of what
// this method does about the epoch case; the re-seal needs a stream_index the durable reserver
// allocates and an outbox nothing in connect owns, and that is open item K1-3.
//
// EVERY REFUSAL IS TAKEN BEFORE THE MAC, and that ordering is not tidiness. message.ComputeWriteAuth
// PANICS on a short key and on an empty nonce rather than answering an error, so a refusal that
// arrived as a recovered panic would be a refusal taken after the damage -- and on a closed
// session, whose writeKey zeroizeOnLoop has already erased, that is exactly the panic waiting on
// the other side of the door. On a refusal the caller's record is untouched, which is
// OpenRecord's own rule one level over: a half-applied re-auth hands an outbox a record it
// believes is fresh.
//
// The group id goes through subtle.ConstantTimeCompare and the epoch through ==, which is
// openRecordOnLoop's own split and guardrail G8's reason: G8 bans bytes.Equal in a FILE rather
// than in a kind of function, so every comparison of OCTETS here goes one way whether or not the
// octets are secret, and an epoch is a u64 and not octets.
//
// THE self.closing CHECK BELOW IS UNREACHABLE, in the shape and for the reason EpochKeys's
// comment measures. It is written anyway because it fails closed, and no property claims it is
// driven: a closed session's refusal comes back out of do.
func (self *GroupSession) ReauthRecord(record *message.Record) error {
	var err error
	if postErr := self.do(func() {
		if self.closing {
			err = ErrSessionClosed
			return
		}
		err = self.reauthRecordOnLoop(record)
	}); postErr != nil {
		return postErr
	}
	return err
}

// reauthRecordOnLoop is ReauthRecord's body. The caller is the loop goroutine.
//
// The two keyed inputs are read off the session HERE, on the loop, and never handed in: write_key
// is written and zeroized by this goroutine, and server_nonce is written by it too, so a body
// that took either as a parameter would be taking a value some other goroutine read.
func (self *GroupSession) reauthRecordOnLoop(record *message.Record) error {
	if record == nil {
		return message.ErrRecordNil
	}
	header := &record.Header
	if subtle.ConstantTimeCompare(header.GroupId[:], self.groupId[:]) != 1 {
		return fmt.Errorf("%w: this record names group %x and this session is keyed for %x",
			ErrRecordNotForThisSession, header.GroupId, self.groupId)
	}
	if header.Epoch != self.epoch {
		return fmt.Errorf("%w: this record is at epoch %d and this session is at %d -- section 5.7 discards an epoch stale record and re-seals it at the new epoch consuming a fresh stream_index, and a re-mac of it would be a tag under write_key[n+1] over a header naming epoch n (open item K1-3)",
			ErrRecordNotForThisSession, header.Epoch, self.epoch)
	}
	// and this is the ONLY statement that writes anything, which is what "one field moves"
	// means when it is read off the source rather than off an assertion.
	record.WriteAuth = message.ComputeWriteAuth(self.writeKey, self.serverNonce,
		header, record.CtHead, header.ServerAttachment)
	return nil
}

// ---------------------------------------------------------------------------
// the body padder, open item M1-7
// ---------------------------------------------------------------------------

// The four octets the length prefix costs, which is the tree's ONE length prefix and not a second
// encoding of the same idea: syntax.WriteOpaqueLP and syntax.ReadOpaqueLP are the pair, and the
// record layer's fixed 32 bit prefix is what every other length in this format is written with.
//
// It is derived from that writer rather than written as 4, so a change to the record layer's
// prefix width moves this with it instead of leaving a padder that overruns its rung by the
// difference.
var lpPrefixBytes = measureLpPrefix()

// measureLpPrefix asks the writer how many octets an empty length prefix costs.
func measureLpPrefix() int {
	writer := syntax.NewWriter()
	writer.WriteOpaqueLP(nil)
	encoded, err := writer.Bytes()
	if err != nil {
		panic(fmt.Errorf("messagegroup: the record layer's length prefix cannot be measured: %w", err))
	}
	return len(encoded)
}

// bucketForBody is the smallest rung of the size ladder a body of this length fits in.
//
// The ladder is walked rather than indexed, and the top of it is SizeBucketBlob rather than a
// written down 5, so a rung added to connect/message moves this bound with it. The blob rung
// itself is not a candidate: it carries no body at all.
func bucketForBody(bodyLength int) (message.SizeBucket, error) {
	want := bodyLength + lpPrefixBytes
	for bucket := message.SizeBucket(0); bucket < message.SizeBucketBlob; bucket += 1 {
		if want <= message.SizeBucketBytes(bucket) {
			return bucket, nil
		}
	}
	return message.SizeBucketBlob, fmt.Errorf("%w: %d octets plus a %d octet length prefix",
		ErrBodyTooLong, bodyLength, lpPrefixBytes)
}

// padBody writes LP(plaintext) into a buffer exactly the rung's length.
//
// THE SCHEME IS THIS FILE'S AND NOT A DOCUMENT'S -- open item M1-7, wire visible, and the
// unpadder below is the only other place that knows it. The length travels INSIDE the aead, so
// the reader recovers it from a value the key authenticated rather than from anything a server
// or an attacker chose; a scheme that put the length outside, or that inferred it from a trailing
// byte pattern, would be recovering a length from an unauthenticated place.
//
// THE TAIL IS ZEROS AND THE WRITER IS WHAT MAKES IT SO. It is inside the aead, so whatever fill
// this side chooses is authenticated -- which means the reader can safely ignore it, and the two
// halves of that are not in tension: one encoding of one message exists because the SEALER emits
// exactly one, not because the opener refuses the others. The fill byte is wire visible under open
// item M1-7 in the sense a second implementation cares about, since two clients padding with
// different bytes produce different ct_body and different body_hash for one message. It is zero,
// and m1w1repairs_test.go pins it octet by octet, because a value no test records is a value the
// next implementer has to guess.
func padBody(bucket message.SizeBucket, bodyPlain []byte) ([]byte, error) {
	rung := message.SizeBucketBytes(bucket)
	if rung < 0 {
		return nil, fmt.Errorf("%w: size bucket %d has no body length", ErrBlobRecordUnsupported, bucket)
	}
	if rung-lpPrefixBytes < len(bodyPlain) {
		return nil, fmt.Errorf("%w: %d octets do not fit the %d octet rung", ErrBodyTooLong, len(bodyPlain), rung)
	}
	writer := syntax.NewWriter()
	writer.WriteOpaqueLP(bodyPlain)
	prefixed, err := writer.Bytes()
	if err != nil {
		return nil, err
	}
	padded := make([]byte, rung)
	copy(padded, prefixed)
	return padded, nil
}

// unpadBody reads LP(plaintext) back out of a rung sized buffer.
//
// It refuses a buffer that is not exactly the rung, which is what stops a truncated or extended
// plaintext being read as a shorter message, and it refuses a length prefix that overruns the
// rung. Both refusals are over octets the aead already authenticated, so reaching either means
// the sealer and the reader disagree rather than that somebody tampered.
//
// The zero tail is NOT checked and that is deliberate, and it does not contradict padBody's
// sentence about it: the aead already covers those octets, so a check here would be a second
// authenticator over authenticated bytes, and a reader that refused a record whose tail was not
// zero would be refusing a record its own key opened. What keeps one message to one encoding is
// that the SEALER emits one fill, not that the opener polices it.
func unpadBody(bucket message.SizeBucket, padded []byte) ([]byte, error) {
	rung := message.SizeBucketBytes(bucket)
	if rung < 0 {
		return nil, fmt.Errorf("%w: size bucket %d has no body length", ErrBlobRecordUnsupported, bucket)
	}
	if len(padded) != rung {
		return nil, fmt.Errorf("%w: %d octets of padded body, want the %d octet rung",
			ErrBodyPadding, len(padded), rung)
	}
	reader := syntax.NewReader(padded)
	bodyPlain, err := reader.ReadOpaqueLP()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBodyPadding, err)
	}
	return bodyPlain, nil
}
