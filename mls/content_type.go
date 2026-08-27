// ContentType belongs to the framing plan, and is declared here because the secret tree
// implements the MessageKeySource interface that plan declares and that interface is keyed
// on it. It is the ONLY name of p6 this package reaches, which is the whole of the
// exception the architecture note carves out.
//
// p6 has not landed in this tree. The honest ways to close that were two: leave the wrapper
// unwritten until it does, or declare what this package needs at the signature the canonical
// interface registry gives it and record the pin. This is the second, and it is the same
// bargain p8's vector harness is already held to -- that surface also landed in this package
// first, under this plan, and p8's own landing replaces it rather than adding a second
// registry beside it. The same applies here: when p6 lands it deletes this file, and until
// then key_schedule_deps_test.go pins the type and its three values so a p6 that arrives
// with a different width or different code points is a build failure in this package rather
// than a content type that routes a commit onto the application ratchet.
//
// A local copy under a private name was the alternative and is worse in the one way that
// matters: two declarations of one wire enum can disagree silently, because the disagreement
// is a number rather than a type error. One declaration, deleted when its owner arrives,
// cannot.
package mls

// ContentType is the framing content type a PrivateMessage header carries, from RFC 9420
// section 6: it selects which of a leaf's two ratchets protects the message.
//
// Its underlying type is the octet the wire format gives it, and no wider. A content type
// decoded at two octets moves every field after it in the header.
type ContentType uint8

// The three content types RFC 9420 section 6 registers. The zero value is deliberately none
// of them -- it is the reserved code point, and a zero that silently meant "application"
// would route an unparseable header onto a real ratchet rather than being refused.
const (
	ContentTypeApplication ContentType = 1
	ContentTypeProposal    ContentType = 2
	ContentTypeCommit      ContentType = 3
)
