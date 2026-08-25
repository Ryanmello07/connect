// The RFC 9420 section 5.1 and 5.2 labelled constructions. Every one of them is a TLS
// presentation language struct, so all of them go through mls/syntax: there is one
// length prefix implementation in the system and one place for a length prefix bug to be.
//
// MLS derives every secret, and signs and macs over, these serialized forms, so a
// preimage that two implementations build differently is a protocol split, and a preimage
// that admits two readings is a signature bypass primitive. That is why nothing here hand
// rolls a prefix.
//
// The whole security argument of this file is the "MLS 1.0 " prefix and the length
// prefixed fields around it, and none of it is observable from the outside: dropping the
// prefix, altering it, dropping the uint16 length, writing the context raw, or
// transposing label and context each produce a well formed output of exactly the
// requested size. Only a published answer separates them, which is what
// crypto_labels_test.go holds this to.
//
// The section 5.2 references carry the same argument one step further. Their two labels
// differ in a single word, and swapping them, or letting both makers share one, produces
// two references that are still 32 bytes, still deterministic and still distinct for
// distinct inputs — while a key package reference and a proposal reference over the same
// bytes have quietly become the same value. No property of the output says which label
// built it, so what holds them is the corpora where another implementation wrote the
// reference down.
package mls

import (
	"bytes"
	"crypto/ed25519"
	"io"

	"github.com/urnetwork/connect/mls/syntax"
)

// The domain separator every MLS label carries before serialization. The version is part
// of it: a future MLS derives different secrets from the same transcript rather than
// silently interoperating with this one.
const MlsLabelPrefix = "MLS 1.0 "

// The sticky writer's error, taken once (convention C2).
//
// Every labelled construction in this file returns bytes and no error, because the
// interface spec A section 3.3 fixes on CryptoProvider has no error return and neither
// does RefHash. That is sound rather than a shortcut: a syntax.Writer's only failure mode
// is a vector longer than its limit, and every value that reaches a labelled construction
// arrived through a decode or an encode already bounded by syntax.MaxVectorLength. A
// panic here is therefore unreachable — and it is a panic rather than a truncation
// because a label that describes more bytes than it carries is exactly the shape a
// signature bypass is built out of.
func mlsLabelBytes(w *syntax.Writer) []byte {
	encoded, err := w.Bytes()
	if err != nil {
		panic("mls: a labelled preimage could not be encoded: " + err.Error())
	}
	return encoded
}

// struct { uint16 length; opaque label<V>; opaque context<V> } KDFLabel, serialized.
//
// The length is the requested output size and not the size of anything in the preimage,
// so two derivations that differ only in how many bytes the caller wanted are still
// separated. The uint16 conversion cannot lose a bit that matters: Expand refuses
// anything above hpkeMaxExpandLength, which is 8160, so a length that survives the call
// is representable, and one that does not stops in Expand rather than deriving under a
// truncated label.
func mlsKdfLabel(label string, context []byte, length int) []byte {
	writer := syntax.NewWriter()
	writer.WriteUint16(uint16(length))
	writer.WriteOpaque([]byte(MlsLabelPrefix + label))
	writer.WriteOpaque(context)
	return mlsLabelBytes(writer)
}

// HKDF-Expand over a preimage that names the label, the context and the output size, so
// no two derivations in the protocol share an info string.
func (self *suiteCryptoProvider) ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte {
	return self.Expand(secret, mlsKdfLabel(label, context, length), length)
}

// The Nh byte derivation with no context. The context field is still written — an empty
// vector is one length byte, not nothing — which is the difference between this and an
// encoder that dropped the field, and the only thing that can see the difference is a
// published answer.
func (self *suiteCryptoProvider) DeriveSecret(secret []byte, label string) []byte {
	return self.ExpandWithLabel(secret, label, nil, self.params.Nh)
}

// The generation is the context, encoded as a big endian uint32 (RFC 9420 section 9). It
// goes through the same writer as everything else: there is one integer encoder in this
// system and it is p1's, so a byte order cannot be chosen twice.
func (self *suiteCryptoProvider) DeriveTreeSecret(secret []byte, label string, generation uint32, length int) []byte {
	writer := syntax.NewWriter()
	writer.WriteUint32(generation)
	return self.ExpandWithLabel(secret, label, mlsLabelBytes(writer), length)
}

// The reference labels of RFC 9420 section 5.2, written out in full because RefHash does
// not add the "MLS 1.0 " prefix: here the prefix is part of the published label rather
// than something a construction contributes.
//
// They are the entire domain separation between the two kinds of reference, and the one
// input neither maker's own behaviour can expose. TestRefLabelsAreTheRfcStrings holds
// them to the RFC's text, and the published Welcome and Commit corpora hold them to a
// reference computed elsewhere, which is what a string this project typed twice cannot do.
const (
	KeyPackageRefLabel = "MLS 1.0 KeyPackage Reference"
	ProposalRefLabel   = "MLS 1.0 Proposal Reference"
)

// struct { opaque label<V>; opaque value<V> } RefHashInput, hashed.
//
// The label is used verbatim. That is not an oversight and not an inconsistency with
// ExpandWithLabel: RFC 9420 section 5.2 defines the reference labels with the prefix
// already inside them, and the crypto-basics vector exercises this with a bare label that
// must not gain one.
//
// Both fields are length prefixed, which is what keeps a reference from being forgeable
// by moving the boundary: without the prefixes, a label ending in the first byte of a
// value and a label one byte shorter hash the same input.
//
// The provider is a parameter rather than a receiver because the reference makers are
// what the tree and the framing layers call, and they hold a CryptoProvider rather than
// the concrete type. No error return, by the registry's fixed signature — see
// mlsLabelBytes for why the writer cannot fail here.
func RefHash(crypto CryptoProvider, label string, value []byte) []byte {
	writer := syntax.NewWriter()
	writer.WriteOpaque([]byte(label))
	writer.WriteOpaque(value)
	return crypto.Hash(mlsLabelBytes(writer))
}

// The reference by which a Welcome addresses a joiner and a proposal names the key package
// it adds. The input is the serialized KeyPackage, not the MLSMessage that carried it.
func MakeKeyPackageRef(crypto CryptoProvider, keyPackage []byte) []byte {
	return RefHash(crypto, KeyPackageRefLabel, keyPackage)
}

// The reference by which a Commit names a proposal it does not carry by value. The input
// is the serialized AuthenticatedContent that framed the proposal and not the Proposal
// itself (RFC 9420 section 5.2), so the reference covers the sender and the signature
// rather than only the proposed change.
func MakeProposalRef(crypto CryptoProvider, authenticatedContent []byte) []byte {
	return RefHash(crypto, ProposalRefLabel, authenticatedContent)
}

// struct { opaque label<V>; opaque content<V> } SignContent, serialized, with the
// "MLS 1.0 " prefix on the label.
//
// The two length prefixes are what make a signature cover one reading of its input rather
// than every reading. Without them a label ending where the content begins and a label one
// byte longer serialize to the same run of bytes, so a signature made for one purpose is a
// valid signature for another over content the signer never saw. That is not a difference
// the primitive can notice: ed25519 signs whatever it is handed.
//
// The prefix is on the label here and not on RefHash's, which is not an inconsistency:
// RFC 9420 section 5.2 writes the reference labels out with the prefix already inside
// them, and section 5.1.2 writes this one without.
//
// No error return, by the interface spec A section 3.3 fixes on the two callers below.
// See mlsLabelBytes for why the writer cannot fail here.
func mlsSignContent(label string, content []byte) []byte {
	writer := syntax.NewWriter()
	writer.WriteOpaque([]byte(MlsLabelPrefix + label))
	writer.WriteOpaque(content)
	return mlsLabelBytes(writer)
}

// The RFC 9420 section 5.1.2 signature: ed25519 over the SignContent preimage rather than
// over the content, so a signature is bound to the purpose it was made for.
//
// The private key is the 32 byte RFC 8032 seed, which is what MLS carries on the wire and
// what the crypto-basics vectors supply. Go's ed25519.PrivateKey is the seed followed by
// the public key, so the expansion happens here and the 64 byte form never leaves this
// function; a caller holding one of those would be storing the public half twice and
// would fail the length check on the way back in.
//
// The length is checked against the registry's NsigPriv rather than against
// ed25519.SeedSize, so the refusal states the suite's own contract rather than this
// primitive's. That is the whole of what it buys, and it is worth being exact about which
// way the safety runs: the registry is the weaker of the two gates here, not the stronger.
// A suite naming a 64 byte private key would pass this check with a 64 byte key and panic
// inside ed25519.NewKeyFromSeed — measured, "ed25519: bad seed length: 64" — where the
// literal would have refused it. What keeps that unreachable is not this line but
// TestEverySuiteNamesTheSignatureSchemeTheProviderComputes, which holds every registered
// suite to ed25519 and to 32 and 32.
func (self *suiteCryptoProvider) SignWithLabel(priv SignaturePrivateKey, label string, content []byte) ([]byte, error) {
	if len(priv) != self.params.NsigPriv {
		return nil, ErrBadSignatureKey
	}
	return ed25519.Sign(ed25519.NewKeyFromSeed(priv), mlsSignContent(label, content)), nil
}

// The inverse, where a failure is always an error and never a logged warning (spec A
// section 5.9, guardrail 7). The caller has no branch to take other than rejecting the
// message, and there is no fallback preimage: a verify that tried the bare label, the
// unframed concatenation or the content itself after this one would accept a signature
// minted for another purpose, which is the whole thing the label exists to prevent.
//
// A wrong key length is ErrBadSignatureKey and a wrong signature length is
// ErrCryptoBadSignature. That split is deliberate. The key is this side's own
// configuration and the length of it is a local bug worth naming; the signature arrived
// from the network, and how it failed is not something an attacker gets to learn.
//
// The key length gate is load bearing: crypto/ed25519.Verify panics on a public key of
// any other length rather than answering. It reads the registry for the same reason
// SignWithLabel's does and with the same caveat — a suite naming 64 would pass it and
// panic in the library, measured, so what makes the gate sufficient is the registered
// suites being held to 32 rather than anything this line does.
//
// The signature length gate is not load bearing, and that is worth writing down rather
// than leaving for the next reader to rediscover. The library refuses every length but 64
// as the first statement of its own verify, so removing this one changes no answer —
// measured over 10260 lengths and bodies from 0 to 512 bytes, 0 disagreements. It stays
// because the contract it states is this package's rather than the library's, and because
// it is the line that would still be right if the suite's signature scheme ever stopped
// being ed25519. TestTheSignatureMethodsAreOnlyTheirOwnPreimage is what holds it there,
// since no input can.
//
// ErrCryptoBadSignature rather than ErrBadSignature: the bare name is errors.go's
// ValSem010, and errors.go wraps this one, so a framing caller can ask either question.
func (self *suiteCryptoProvider) VerifyWithLabel(pub SignaturePublicKey, label string, content []byte, sig []byte) error {
	if len(pub) != self.params.NsigPub {
		return ErrBadSignatureKey
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrCryptoBadSignature
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), mlsSignContent(label, content), sig) {
		return ErrCryptoBadSignature
	}
	return nil
}

// A fresh signature key pair, seeded from this provider's own source.
//
// The seed is read from self.random rather than from crypto/rand, which is what lets a
// test assert that the bytes offered are the bytes used, in order, and lets an interop
// failure reproduce byte for byte. ed25519.GenerateKey would be the obvious call and is
// deliberately not made: it substitutes crypto/rand.Reader for a nil reader, so a provider
// built over a caller's source that turned out to be nil would silently generate from the
// operating system and the pinned case would stop reproducing. Reading here means a nil
// source fails loudly instead.
//
// A short or failing source is an error rather than a panic, because this method has an
// error return where Random does not. What it must never be is a key: a seed assembled
// from a partial read is a tail of zeroes nobody chose, and it would sign and verify
// perfectly.
//
// The public half is copied out of the expanded key rather than sliced from it. No input
// can see the difference — measured over 65536 key pairs: the bytes agree, two calls never
// share storage either way, and neither form aliases the seed. What a slice would do is
// keep the whole 64 byte expanded key reachable from the public key, and its first 32 bytes
// are the secret seed, so a caller holding only a public key would be holding a private one
// as well. TestTheSignatureMethodsAreOnlyTheirOwnPreimage is what holds it, by reading this
// statement rather than by asking the answer a question it cannot hear.
//
// The private half is the seed buffer and not expanded[:32], which is a difference an input
// can see even though the bytes never differ: a window onto the expanded key has room for
// 32 more, so a caller appending to what it was told is a private key writes over the public
// half of the same pair. TestSignatureKeyPairAnswersStorageOfItsOwn is that assertion.
func (self *suiteCryptoProvider) SignatureKeyPair() (SignaturePrivateKey, SignaturePublicKey, error) {
	seed := make([]byte, self.params.NsigPriv)
	if _, err := io.ReadFull(self.random, seed); err != nil {
		return nil, nil, err
	}
	expanded := ed25519.NewKeyFromSeed(seed)
	return SignaturePrivateKey(seed), SignaturePublicKey(bytes.Clone(expanded[ed25519.SeedSize:])), nil
}
