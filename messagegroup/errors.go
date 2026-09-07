// The client half's sentinels: every refusal a caller of this package can catch by name, in
// one place, so a reader asking what can go wrong reads a file rather than a call graph.
//
// It is a second errors.go rather than a widening of connect/message's, and the split is the
// reason. Spec A section 12.1 publishes a block of names to the message server and
// connect/message's errors.go is written as an argument about which of its sentinels are on
// that block; none of the ones here can be. The server never derives a storage root, never
// holds a class key and never opens a record -- section 12.1 gives it no decryption function
// at all -- so a sentinel it cannot reach would widen its allow list with a name no server
// can match. xwing_errors.go already applies that rule one file over, for the four errors of
// a KEM the server never runs, and this file is the same rule for the rest of the client
// half.
//
// Each one is fatal by construction. Nothing in this package reports a cryptographic failure
// and carries on: a record that does not open is not a warning, it is a message a member
// cannot read, and a layer that answered plaintext beside the error would hand its caller
// octets no key authenticated.
package messagegroup

import "errors"

var (
	// Fires when a record aead key is not the thirty two octets section 5.3's expansion
	// produces. It is checked before the primitive is constructed rather than left to
	// chacha20poly1305.NewX's own length check, so the refusal names the record layer's
	// contract -- key_head and key_body are the first thirty two octets of a fifty six octet
	// expansion -- rather than the library's.
	ErrRecordAeadKeyLength = errors.New("messagegroup: a record aead key is not the thirty two octets the record key expansion produces")
	// Fires when a record aead nonce is not the twenty four octets XChaCha20-Poly1305 takes.
	// This is the width that tells the extended construction from the twelve octet one, and
	// it is the reason this refusal exists at all: a twelve octet nonce is the tail of the
	// expansion silently discarded, and every record so sealed round trips against itself and
	// against nothing else.
	ErrRecordAeadNonceLength = errors.New("messagegroup: a record aead nonce is not the twenty four octets XChaCha20-Poly1305 takes")
	// Fires when a record ciphertext does not authenticate under the key, the nonce and the
	// aad it was opened with. It carries no plaintext with it and never a partial one: the
	// only thing an unauthenticated ciphertext yields is the refusal.
	ErrRecordAeadOpen = errors.New("messagegroup: a record ciphertext did not authenticate")
	// Fires when a group handle key is not the thirty two octets HKDF-Expand(storage_root[0],
	// "gh/v1", 32) produces. A handle derived from a truncated key is a well formed handle,
	// and every member of the group would compute a different one, so the width is refused
	// where it can still be told apart from a value.
	ErrGroupHandleKeyLength = errors.New("messagegroup: a group handle key is not the thirty two octets the epoch zero expansion produces")
	// Fires when a storage root is not the thirty two octets HKDF-Extract produces. It is
	// the same argument ErrGroupHandleKeyLength makes one derivation later: every key of an
	// epoch hangs off this value, a truncated or an over long one expands to well formed
	// keys, and no other member of the group computes them. Without it the refusal came
	// from mls's own expand -- which names mls's contract, and only for a root SHORTER than
	// the hash, so a root of sixty four octets decoded out of durable storage was accepted
	// silently.
	ErrStorageRootLength = errors.New("messagegroup: a storage root is not the thirty two octets HKDF-Extract produces")
	// Fires when a retention class key is not the thirty two octets DeriveClassKeys
	// produces. record_key[0] binds the class key, so a truncated one is a whole ladder no
	// peer reproduces.
	ErrClassKeyLength = errors.New("messagegroup: a class key is not the thirty two octets the class expansion produces")
	// Fires when a record key is not the thirty two octets the ladder produces. Every aead
	// key and every nonce of a record is expanded from it, so a wrong width here is a
	// record nothing opens -- and, on the ratchet's own path, a chain that silently forks.
	ErrRecordKeyLength = errors.New("messagegroup: a record key is not the thirty two octets the record key ladder produces")
	// Fires when a record aead is asked to seal against no additional authenticated data.
	// MASTER invariant I7 makes ct_head aad_head's and ct_body aad_body's, and the header of
	// sealRecordAead used to state that as if something enforced it. Nothing did: a nil aad
	// sealed and returned a ciphertext whose epoch, stream index, sender and retention class
	// were authenticated by nothing at all.
	ErrRecordAeadAadMissing = errors.New("messagegroup: a record aead was asked to seal against an empty aad")
	// Fires when a stream index reservation is asked to go backwards -- a persisted high
	// water behind an index already handed out, or an allocation that came back below the
	// ladder standing on it. Spec A section 5.6 makes the counter write once, so a rewind is a
	// store that lost a flush, and every index above it is a nonce this device may already
	// have used.
	ErrStreamIndexRewound = errors.New("messagegroup: a stream index reservation is behind an index already reserved")
	// Fires when the store cannot allocate the next index of a stream at all: its next
	// position is one it has already handed out and it has no way past it. Under ruling A1 the
	// counter is the store's, so this is the store reporting a state it cannot leave rather
	// than a caller being told no -- and the underlying hazard is the one section 5.6 spells
	// out, that a reused stream index is a reused nonce under a reused record key, which is a
	// total break of both of a record's aeads.
	ErrStreamIndexConsumed = errors.New("messagegroup: a stream index has already been consumed")
	// Fires when a stream index reserver is nil where one is required. The reservation is
	// ordered BEFORE the key, so a ratchet without a sink is a ratchet that cannot make the
	// ordering it exists to make -- and section 5.6 says the constructor takes the sink to
	// make that explicit.
	ErrNilStreamIndexReserver = errors.New("messagegroup: a stream index reserver is required and none was given")
	// Fires when a sender ratchet has produced the last stream index a u64 can hold. A wrap
	// to zero is not a wasted message: it re-issues every record key and every nonce this
	// sender has ever used, under a class key that has not moved.
	ErrSenderRatchetExhausted = errors.New("messagegroup: a sender ratchet has consumed the last stream index")
	// Fires when a receiver is asked for a record key outside its skipped key window --
	// above it, or below a head that has already passed. Spec A section 5.5 makes this
	// visible rather than silent: the caller turns it into a gap entry, never into a
	// dropped message. Open item M1-15 decides how it crosses OpenRecord.
	ErrOutOfWindow = errors.New("messagegroup: a record key is outside this receiver's skipped key window")
	// Fires when a receiver window size or a retained key bound is not positive. A window of
	// zero would refuse every out of order record and a negative one is not a bound at all,
	// so the constructor states it rather than clamping it.
	ErrWindowSize = errors.New("messagegroup: a receiver window size or retained key bound is not positive")
	// Fires when a record key is asked of a sender this table tracks no ratchet for. It is a
	// refusal and not an empty answer because the caller's next move differs: a ratchet that
	// was never installed is a member this session does not know about, and a key of zero
	// octets would open a record with a key every party in the world can compute.
	ErrNoReceiverRatchet = errors.New("messagegroup: no receiver ratchet is tracked for this sender and retention class")
)

// ---------------------------------------------------------------------------
// the group engine and its connect/mls adapter, spec A section 6
// ---------------------------------------------------------------------------

var (
	// Fires when an engine is constructed with no crypto provider. Every secret the engine
	// derives is drawn through it, so there is nothing the constructor could have judged
	// without one -- and a nil provider reached at the first group is a dereference in a
	// caller's founding path rather than a refusal it can report.
	ErrEngineCryptoProvider = errors.New("messagegroup: a group engine requires a crypto provider and none was given")
	// Fires when an engine is constructed with no state store. A group with nowhere to persist
	// an epoch is a group that cannot be reopened, and the first thing that would notice is a
	// restart.
	ErrEngineStateStore = errors.New("messagegroup: a group engine requires a state store and none was given")
	// Fires when an engine is constructed with no signature private key. The leaf of every
	// group this engine founds is signed with it, so an empty signer is a group whose own
	// founding leaf verifies against nothing.
	ErrEngineSigner = errors.New("messagegroup: a group engine requires a signature private key and none was given")
	// Fires when the encoded urmessage_leaf_keys body a device publishes cannot be read. It is
	// refused at construction rather than at the first group because a device that cannot say
	// what its wrap target key is has nothing to fix later: every group it founds would carry
	// a leaf no epoch fan out can address.
	ErrEngineLeafKeys = errors.New("messagegroup: an urmessage_leaf_keys body is not one this engine can read")
	// Fires on every call of the connect/mls adapter's JoinFromWelcome, because the method
	// cannot be written over connect/mls's exported surface at all: mls.NewKeyPackage keeps the
	// signature private half of the leaf it mints on an unexported field and
	// mls.StateStore.TakeKeyPackage does not carry it, so no caller outside package mls can
	// assemble the mls.JoinKeyMaterial a Welcome join takes. It fails CLOSED and it looks like
	// what it is, which is this project's own rule about a missing key source; a join answering
	// a handle built on a signature key this device does not hold would be a member every peer
	// refuses, discovered at the first commit rather than here.
	ErrEngineJoinUnavailable = errors.New("messagegroup: this engine cannot join from a welcome, because connect/mls does not publish the joiner's own signature private key")
	// Fires when MemberAt is asked for an ordinal the membership does not have. It is a
	// refusal and not a zero member because the two are told apart by nothing downstream: a
	// projection that dropped mls.MemberAt's second result would turn a missing member into
	// leaf 0, addressed, wrapped to and counted.
	ErrEngineMemberOrdinal = errors.New("messagegroup: no member of this group stands at that ordinal")
	// Fires when a member's leaf carries no readable urmessage_leaf_keys extension. The epoch
	// fan out wraps to that key, so a nil answer here is a member silently left out of an
	// epoch every other member can open.
	ErrEngineMemberLeafKeys = errors.New("messagegroup: a member's leaf carries no urmessage_leaf_keys extension this engine can read")
	// Fires when ApplyCommit is handed an EngineProcessed this handle did not stage -- one
	// built by a keyed composite literal outside this package, which section 6 says is legal
	// go, or one staged by another handle of this package. It is a typed refusal and never a
	// panic and never a silent no-op, so the guarantee is "the commit THIS handle staged"
	// rather than "some commit some engine staged".
	ErrEngineProcessedForeign = errors.New("messagegroup: this handle did not stage that processed message")
	// Fires when connect/mls answers a processed message whose discriminant and whose arms
	// disagree, or an opened application message with no content. Neither is a state mls can
	// produce today; the refusal is here because the alternative to refusing it is a zero
	// plaintext from leaf 0, which reads as an empty message rather than as a fault.
	ErrEngineProcessedArm = errors.New("messagegroup: a processed message's kind and its content disagree")
)

// ---------------------------------------------------------------------------
// the two ratchets, spec A section 5.5
// ---------------------------------------------------------------------------

var (
	// Fires when a ratchet that has been zeroized is asked for a key. Without it Zeroize left
	// both ratchets fully operational and the next call handed out the ladder rung derived
	// from thirty two zeros -- the SAME key, and so the same (key, nonce) pair, for every
	// zeroized ratchet in the world, with the stream index durably consumed under it.
	ErrRatchetZeroized = errors.New("messagegroup: this ratchet has been zeroized and can produce no further keys")
	// Fires when a sender ratchet can never serve another allocation its store makes. Three
	// ways in and every one is permanent for that ratchet: the store refused to allocate at
	// all, the store handed back an index at or below the one the ladder stands on, or it
	// handed back one so far ahead that the catch-up walk exceeds maxLadderWalk -- which under
	// ruling A1's shared counter is what a class that went quiet for a whole sender's stream
	// meets, with no corrupt store in it. It is separated from a transient failure because the
	// two need opposite answers: a full disk is a retry and the ladder does not move, while
	// none of these three becomes true later, so a ratchet that went on asking would refuse
	// every send forever while paying a durable write per attempt. The error wraps the
	// underlying sentinel -- ErrStreamIndexConsumed, ErrStreamIndexRewound or
	// ErrLadderWalkTooLong -- so a caller can tell the three apart with errors.Is.
	ErrSenderRatchetWedged = errors.New("messagegroup: this sender ratchet can no longer serve the stream indices its store allocates")
	// Fires when a ladder resume would cost more expansions than this package will pay. Both
	// constructors walk one HKDF-Expand per index below their starting point, and neither the
	// stream index in a record's cleartext header nor a high water read back out of a store is
	// authenticated by anything at the moment it is read -- so an unbounded walk is a denial
	// with no ceiling. See maxLadderWalk for what the bound is and why it is a cost ceiling
	// rather than a class.
	ErrLadderWalkTooLong = errors.New("messagegroup: a ladder resume would cost more expansions than this package will pay")
)

// ---------------------------------------------------------------------------
// the session, the sealer and its reader, spec A sections 5.2 and 5.5
// ---------------------------------------------------------------------------

var (
	// Fires when a session is constructed with no group handle. The handle is what the epoch's
	// mls_secret is exported through, so a session without one holds no key material at all.
	ErrNilGroupHandle = errors.New("messagegroup: a group session requires a group handle and none was given")
	// Fires when a session is constructed with no clock. expire_at is a clock read and the
	// house rule forbids a timing sensitive test, so the clock is injected -- and a nil one
	// defaulting to time.Now would put a real clock in a package that has none.
	ErrNilClock = errors.New("messagegroup: a group session requires an injected clock and none was given")
	// Fires when a session is constructed with no server nonce, or when the nonce is replaced
	// with an empty one. write_auth is a mac over the submitting connection's nonce and
	// connect/message refuses an empty one; refusing it here names the session's own missing
	// state rather than the preimage builder's.
	ErrSessionServerNonce = errors.New("messagegroup: a group session requires the submitting connection's server nonce")
	// Fires when a closed session is asked to seal or open. Close zeroizes every key the
	// session holds, so the alternative to this refusal is a record sealed under thirty two
	// zeros.
	ErrSessionClosed = errors.New("messagegroup: this group session is closed")
	// Fires when a session is constructed or advanced with no pq_secret. Task 13 produces it
	// and there is no default, which is the point: HKDF-Extract(mls_secret, 32 zero bytes)
	// produces a perfectly good storage root, both clients agree, every test passes, and the
	// post quantum half of the design is silently gone. A missing key schedule fails closed
	// and looks like what it is; a placeholder one fails open and looks like a working
	// messenger.
	ErrNilPqSecret = errors.New("messagegroup: a group session requires a pq_secret and there is no default")
	// Fires when a session is opened at an epoch after zero with no epoch zero group handle
	// key. group_handle_key is fixed at group creation and is PERSISTED state; a constructor
	// that recomputed it from the current epoch would give every epoch a different
	// sender_handle, so a member's stream would end at every commit.
	ErrEpochZeroHandleKeyMissing = errors.New("messagegroup: a session past epoch zero requires the group handle key it was founded with")
	// Fires when a record is sealed with an expire_at that has already passed. It is advisory
	// and may only shorten retention, so a value in the past is a record the server is entitled
	// to prune before anyone reads it -- which is a caller's mistake and not a policy.
	ErrRecordExpired = errors.New("messagegroup: a record's expire_at has already passed")
	// Fires when a retention class other than DURABLE reaches SealRecord. MASTER section 8.1
	// says ct_head is always under the durable class and section 5.3 hands both aead
	// derivations one record_key[i]; for a DURABLE record the two readings coincide and for
	// every other class they do not. Open item M1-6 rules it. Until then this is a refusal and
	// never a guess, because a PERMANENT or an EPH record sealed under the wrong reading is
	// wire visible and unrecoverable after the A6 freeze.
	ErrRetentionClassUnruled = errors.New("messagegroup: only the durable retention class is sealed until open item M1-6 rules which record key seals ct_head")
	// Fires when a stage of the seal chain is reached with the value the previous stage owed it
	// missing. Section 5.2's title is "Construction order is a type, not a convention" and the
	// staging types are unexported, so the order IS a type to every other package; inside this
	// one a keyed composite literal can assemble a later stage over an earlier stage's zero
	// value, and a head sealed that way produced a record with body_hash all zero that
	// message.EncodeRecord accepted. Each stage carries what the next needs and the next checks
	// it, so a skipped stage is this refusal rather than a wire visible record no reader opens.
	ErrRecordStageOrder = errors.New("messagegroup: a record was assembled out of the order MASTER section 8 fixes")
	// Fires when a body plaintext does not fit any rung of the size ladder. The ladder tops out
	// at the 64 KiB rung and the blob rung carries no body at all, so a longer body is a blob
	// and a blob is task 20's.
	ErrBodyTooLong = errors.New("messagegroup: a record body is longer than the largest rung of the size ladder")
	// Fires when a padded body does not unpad. The length prefix is inside the aead, so
	// reaching this means the plaintext authenticated and is still not a padded body -- which
	// is a sealer and a reader that disagree rather than an attacker.
	ErrBodyPadding = errors.New("messagegroup: a record body did not unpad")
	// Fires when a record on the blob rung reaches the sealer or the reader. The blob object,
	// its identifier and its padder are task 20's and none of them exists yet; a record whose
	// body lives somewhere this package cannot address is refused rather than opened empty.
	ErrBlobRecordUnsupported = errors.New("messagegroup: a record on the blob rung has no body this package can reach yet")
	// Fires when a record names a group, an epoch or a sender this session is not keyed for.
	// The header is cleartext and authenticated by nothing at the moment it is read, so each
	// of the three is checked against the session's own state before any key is derived --
	// and a record whose sender_handle is not the one the ratchet is keyed by would otherwise
	// be opened under a ladder belonging to somebody else.
	ErrRecordNotForThisSession = errors.New("messagegroup: this record names a group, an epoch or a sender this session is not keyed for")
	// Fires when a member or a device finds no device wrap for its target at an epoch after
	// the marker has landed. Spec A section 5.11 step 5 makes it a VISIBLE failure -- a gap
	// entry with reason no_wrap -- and never a silent skip. It is declared here beside
	// ErrOutOfWindow because open item M1-15 has not decided how either crosses OpenRecord,
	// and the two sentinels are what sdk matches on until it does. Wave 2's fan out is what
	// returns it; nothing in wave 1 does.
	ErrNoWrap = errors.New("messagegroup: no device wrap for this target at this epoch")
)
