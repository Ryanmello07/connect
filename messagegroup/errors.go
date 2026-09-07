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
)
