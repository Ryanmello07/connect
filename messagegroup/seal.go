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
// The four functions the order runs through already carry it in their SIGNATURES, and this file
// derives nothing: AADBody takes a BodyBinding with no hash within reach, which is guardrail G4
// built as a signature; AADHead reads body_hash off the header; WriteAuthPreimage takes
// H(ct_head); ComputeWriteAuth closes it.
//
// THREE DECISIONS THIS FILE TAKES, AND SAYS IT IS TAKING.
//
// (a) WHICH record_key SEALS THE HEAD. MASTER section 8.1 says "ct_head is always under the
// durable class" and section 5.3 hands both aead derivations one record_key[i]. For a DURABLE
// record the two readings coincide; for every other class they do not. Open item M1-6 rules it.
// Until then a class other than DURABLE is REFUSED, with a sentinel naming the item -- a refusal
// and not a guess, because a PERMANENT or an EPH record sealed under the wrong reading is wire
// visible and unrecoverable after the A6 freeze. That refusal blocks wave 2's tasks 14 and 15,
// which is why M1-6 sits under "blocking CP3b" and not under the format freeze, and no exemption
// is carved here for either of them: four exemptions is a refusal that has become a sentence.
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
// The class is refused unless it is DURABLE. See decision (a) at the top of this file; the
// refusal names open item M1-6 and is the only thing standing between an unruled reading of
// MASTER section 8.1 and a wire visible record nobody can re-derive.
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

	if class != message.RetentionDurable {
		return nil, fmt.Errorf("%w: this record names class %d bucket %d", ErrRetentionClassUnruled, class, ephBucket)
	}
	if expireAt != 0 && expireAt <= uint64(self.nowMs()) {
		return nil, fmt.Errorf("%w: expire_at %d is not after now", ErrRecordExpired, expireAt)
	}
	builder, err := self.newRecordBuilderOnLoop(class, ephBucket, isCommit, len(bodyPlain), expireAt, serverAttachment)
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
	isCommit bool, bodyLength int, expireAt uint64,
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
	ratchet, err := self.senderRatchetOnLoop(class, retentionWire)
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
			GroupId:          self.groupId,
			SenderHandle:     self.senderHandle,
			Epoch:            self.epoch,
			StreamIndex:      streamIndex,
			IsCommit:         isCommit,
			RetentionClass:   class,
			EphBucket:        ephBucket,
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

// bindBodyHash writes H(ct_body) into the header.
//
// It is SHA-256 OF THE CIPHERTEXT and never of the plaintext, and never of the unpadded
// plaintext: section 5.1 keeps body_hash after ct_body has been pruned, so it is what a pruned
// record still says about what it carried, and a hash of anything else would be a value no
// holder of the record can recompute.
func (self *recordBodySealed) bindBodyHash() *recordBodyBound {
	self.builder.header.BodyHash = sha256.Sum256(self.ctBody)
	return &recordBodyBound{sealed: self}
}

// recordBodyBound is the third stage: the header is complete and nothing of the head exists.
type recordBodyBound struct {
	sealed *recordBodySealed
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
	if header.RetentionClass != message.RetentionDurable {
		return nil, nil, fmt.Errorf("%w: this record names class %d bucket %d",
			ErrRetentionClassUnruled, header.RetentionClass, header.EphBucket)
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
	ratchetKey := ReceiverRatchetKey{SenderHandle: header.SenderHandle, RetentionWire: retentionWire}
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
// The tail is zeros. It is inside the aead too, so it authenticates, and a reader that ignored it
// would be accepting two encodings of one message.
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
// The zero tail is NOT checked and that is deliberate: checking it would make the padding a
// second authenticator over bytes the aead already covers, and a reader that refused a record
// whose tail was not zero would be refusing a record its own key opened.
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
