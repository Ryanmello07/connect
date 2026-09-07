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
	// water behind an index already handed out. Spec A section 5.6 makes the counter write
	// once, so a rewind is a store that lost a flush, and every index above it is a nonce
	// this device may already have used.
	ErrStreamIndexRewound = errors.New("messagegroup: a stream index reservation is behind an index already reserved")
	// Fires when an index that has already been consumed is reserved a second time. This is
	// the one section 5.6 spells out: a reused stream index is a reused nonce under a reused
	// record key, which is a total break of both of a record's aeads.
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
