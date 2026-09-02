// Typed errors for the X-Wing hybrid key encapsulation. Every one of them is fatal by
// construction, for the reason errors.go states over the whole package: a wrap that does not
// open is not a warning, it is a member who cannot read the epoch, and a KEM that reported one
// and carried on would hand the layer above it thirty two bytes that are not a shared secret.
//
// They are here rather than in errors.go because that file's opening comment is an argument
// about which of its sentinels spec A section 12.1 publishes to the server, and none of these
// four is on that surface at all: the server never wraps, never unwraps and never holds an
// X-Wing key, so an error it cannot reach is one that would widen its allowlist with a name no
// server can match. That is the same rule errors.go applies to the four it keeps off the block,
// applied one file over.
package message

import "errors"

var (
	// Fires when a seed is not the thirty two octets draft-connolly-cfrg-xwing-kem section 5.2
	// makes an X-Wing private key. It is the G9 hazard's front door: the ML-KEM seed this
	// expands to is sixty four, and a caller holding one of those has a value that is neither
	// an X-Wing seed nor a refusal unless the length is checked here.
	ErrXwingBadSeedSize = errors.New("message: xwing seed must be 32 bytes")
	// Fires when an encapsulation key is not the 1216 octets the draft gives it. Checked before
	// any parsing, so a truncated or over long key never reaches ML-KEM's own decoder, which
	// would report the ML-KEM half's length rather than the X-Wing key's.
	ErrXwingBadPublicKeySize = errors.New("message: xwing public key must be 1216 bytes")
	// Fires when a ciphertext is not the 1120 octets the draft gives it. A wrap ciphertext
	// arrives from the server, so every octet of it is attacker controlled and its length is the
	// one thing that must be settled before any arithmetic runs over it.
	ErrXwingBadCiphertextSize = errors.New("message: xwing ciphertext must be 1120 bytes")
	// Fires when the x25519 half of an encapsulation or a decapsulation produced no usable
	// secret, which crypto/ecdh answers for a low order point. The draft states no such check;
	// spec A section 5.4 requires one, and refusing is the only answer that does not combine an
	// all zero shared secret into a key both ends would agree on and neither would have chosen.
	ErrXwingInvalidPoint = errors.New("message: xwing x25519 produced an invalid shared secret")
)
