// Where a group context's AUTHORITY comes from, answered with a type rather than with a walk
// over the source.
//
// THE QUESTION THIS FILE EXISTS FOR. The proposal cache binds itself to one group and one epoch,
// and that binding is only worth the authority of the value it was taken from. This package
// decodes a GroupContext straight off peer octets -- (*GroupInfo).UnmarshalMLS calls
// decoded.GroupContext.UnmarshalMLS, and a GroupInfo is what a joiner is handed inside a Welcome
// -- so "the argument's type is *GroupContext" says nothing whatever about whose epoch a cache is
// about to believe it is in. An attacker choosing a group id and an epoch of 1<<40 writes a
// perfectly well typed *GroupContext.
//
// THREE ROUNDS ANSWERED THAT WITH AN AST GATE AND ALL THREE WERE BYPASSED, each time by ordinary
// Go that a reader would write on purpose:
//
//  1. It read the argument's TYPE. Any *GroupContext passed, decoded or not.
//  2. It walked the selection chain to its ROOT and refused a root this package decodes. One
//     local structure between the decode and the bind passed --
//     type joinStateMutation struct{ context GroupContext } -- and the gate LOGGED the
//     laundering as acceptable, because a joinStateMutation is not a type this package decodes.
//  3. It refused any chain that CROSSED a decoded type. Bypassed twice more. By an ordinary
//     accessor -- NewProposalCache(info.Context()) -- because the walk deliberately does not
//     record a method call's receiver as crossed, so that (*GroupContext).Clone, the remedy that
//     same gate prescribed, stays acceptable. And by EMBEDDING --
//     type joiningGroup struct{ GroupInfo } with &self.GroupContext -- because the walk reads
//     TypeOf(node.X) and never consults the type checker's Selections, which is where the index
//     path of a promoted selection lives. The gate refused the named-field spelling of the
//     identical structure and accepted the embedded one.
//
// THREE BYPASSES IN THREE ROUNDS IS NOT BAD LUCK, and round three's own exemption is the tell.
// "A call ON a value answers the provenance of that value rather than a new one" is TRUE of
// Clone, which returns the receiver's own type, and FALSE of any accessor that returns an inner
// value reached through a field. Nothing in the shape separates them, so the walk accepted both.
// Provenance is where a value CAME FROM, and where a value came from is not a property of the
// text it is written in -- which is why each round's fix was a shape the next reader bypassed by
// writing the advice down. The gate is deleted rather than sharpened, because a fourth walk kept
// beside a type that cannot be bypassed would tell the next reader the question is harder than
// it is.
//
// WHAT REPLACES IT. VerifiedGroupContext is a distinct type whose only field is unexported, so no
// declaration outside this package can build one carrying a context however it is spelled, and
// inside this package the declarations that build one are a class the compiler can enumerate: a
// composite literal with an element, or a write of the field, and there is no third spelling in
// Go. NewProposalCache and Rebind take THAT and not a *GroupContext, so every bypass above stops
// COMPILING rather than stopping a gate -- a decoded context cannot be laundered through a local
// struct, an accessor method or an embedded wire type, because none of those produce a value of
// the right type.
//
// WHERE THE VERIFICATION ACTUALLY HAPPENS, which is the design fact this file is really about.
// There is exactly one place in this package where a group context stops being octets somebody
// sent and becomes a value this client vouches for, and it is not a signature check -- there is
// no GroupInfo signature verification in this package at all, and welcome_wire.go says so out
// loud: signing a GroupInfo and joining from one are the group lifecycle's. It is the EPOCH'S OWN
// KEY SCHEDULE. Every constructor of a KeySchedule expands over the serialized GroupContext and
// keeps those exact bytes, and confirmation_key is one DeriveSecret off the epoch_secret that
// expansion produced. So a confirmation tag that verifies under this schedule is a statement by a
// party that knew this epoch's secrets about THIS context and no other: change one octet of the
// group id, the epoch, the tree hash or the transcript hash and the schedule derives a different
// confirmation key, and the tag this client was handed stops verifying. That is why the
// constructor is a method of *KeySchedule and takes no group context at all -- there is nothing
// in its signature to launder.
//
// It covers all three paths a lifecycle has. A JOINER derives the schedule from the joiner_secret
// it decrypted out of a Welcome sealed to its own init key, over the GroupInfo's context, and the
// GroupInfo's confirmation tag is what says a member published it. A MEMBER PROCESSING A COMMIT
// derives the new epoch's schedule and checks the commit's confirmation tag, which is ValSem205
// and is a check it already owed. A CREATOR samples its own epoch_secret and computes its own
// tag, which is trivially true and honestly so: the authority there is that this client built the
// context, and the door is the same one. Nothing needs a second constructor, and if a later task
// finds a path that does, the derived gate in group_context_verified_test.go fails until somebody
// writes down what it is -- which is the conversation that has been missing every time this
// question was answered before.
//
// WHAT IT DOES NOT CLAIM. Not that the context is CORRECT: whether the tree hash matches the
// ratchet tree, whether the signer was entitled to sign, whether this member belongs in the group
// at all are validations of their own and this type is not a substitute for any of them. What it
// claims is exactly what the tag proves, and that claim is the one the cache's binding needs --
// this group and this epoch were named by a party holding the epoch's confirmation key.
package mls

import (
	"errors"
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// errUnconfirmedGroupContext is the refusal when a tag does not confirm this epoch's context.
//
// Unexported because nothing outside this package holds a VerifiedGroupContext to be refused one
// for, which is the reason proposal_list.go's own invariants are unexported. It is a value of its
// own rather than the crypto layer's ErrCryptoBadSignature because the two send a caller to
// different places: a bad signature is a message somebody forged, and this is a member whose view
// of the epoch is not this member's -- the fork ValSem205 exists to report.
var errUnconfirmedGroupContext = errors.New(
	"mls: the confirmation tag does not confirm the group context this epoch's schedule was derived over")

// VerifiedGroupContext is a group context whose authority has been established, and it is the
// only thing the proposal cache will bind an epoch to.
//
// ONE UNEXPORTED FIELD, AND THAT FIELD IS THE WHOLE MECHANISM. A struct whose only field is
// unexported cannot be built carrying a value from any other package -- mls.VerifiedGroupContext{}
// compiles out there and is the zero value, which every door refuses, and there is no spelling
// that reaches the field. Inside this package the class of declarations that can build one is
// what the compiler already enumerates -- a composite literal with an element, or a write of the
// field -- and TestEveryConstructionOfAVerifiedGroupContextIsClassifiedHere derives exactly that
// class off the source and holds it to a table. That is a question about source SHAPE and it has
// a shape answer, which is precisely what "where did this value come from" did not.
//
// A POINTER TO A CONTEXT AND NOT A CONTEXT, so that the zero value is telling. A
// VerifiedGroupContext holding a GroupContext by value would have a zero value that reads as a
// perfectly ordinary context -- the empty group at epoch 0 -- and a forged one would bind a cache
// to that pair with no door able to notice. Held behind a pointer, the zero value carries nil and
// every consumer refuses it with ErrNilGroupContext, which is the same refusal a caller that
// passed nothing at all gets.
//
// THE CONTEXT IT HOLDS IS ITS OWN. ConfirmGroupContext decodes the schedule's own bytes into a
// fresh structure, so nothing a caller still holds aliases what this value vouches for and no
// later write through a caller's slice can change the group a cache believes it is in. Context()
// hands out a Clone for the other half of that.
type VerifiedGroupContext struct {
	inner *GroupContext
}

// Context answers a COPY of the context this value vouches for, or nil for a value that vouches
// for nothing.
//
// A copy, because the point of the type is that the value cannot be changed after it was
// verified: handing out the pointer would let any holder rewrite the group id of a context a
// cache has already bound to, and the cache's own copy of the binding is not what a later caller
// would be comparing against.
//
// Nil rather than a panic for the zero value, so that a caller that got hold of one has an answer
// it can act on. Nothing in this package builds a zero VerifiedGroupContext; another package can
// spell one, and this is what it gets.
func (self *VerifiedGroupContext) Context() *GroupContext {
	if self == nil || self.inner == nil {
		return nil
	}
	return self.inner.Clone()
}

// ConfirmGroupContext answers the group context this epoch's schedule was derived over, as a
// value whose authority is established, once the confirmation tag proves a holder of this epoch's
// confirmation key named it.
//
// IT TAKES NO GROUP CONTEXT, and that is the whole of why it cannot be laundered. Every other
// shape of this constructor -- one taking the context to vouch for, or the GroupInfo it came out
// of -- would be a door a decoded value could be handed to, and this file exists because three
// rounds of trying to police such a door failed. There is nothing in this signature to police:
// the context comes out of the schedule's OWN groupContextBytes, which are the bytes the
// epoch_secret was expanded over, so the value answered is the one the tag is about by
// construction rather than by a check somebody has to remember to write.
//
// THE BYTES ARE DECODED RATHER THAN A RETAINED STRUCT COPIED. It is the same fact stated the
// stronger way: what an epoch's keys were derived from is the OCTETS, and decoding them back is
// what says the answer is that and not a struct that has since been edited beside them. It also
// leaves KeySchedule's own storage the shape every gate over that type reads today, which a
// second retained field would not.
//
// THE COMPARISON IS (*KeySchedule).VerifyConfirmationTag AND NOTHING ELSE, which is guardrail 8
// one type up: it reaches CryptoProvider.MacVerify and therefore
// crypto/subtle.ConstantTimeCompare, it refuses a length mismatch ahead of the comparison rather
// than accepting a prefix, and it refuses outright over an epoch whose confirmation_key has been
// erased -- an erased key is KDF.Nh zero bytes, which every party can compute, so a tag over it
// authenticates nobody and a context confirmed by one would be confirmed by an attacker.
//
// AN UNCONFIRMED TAG IS AN ERROR AND NOT A BOOL. The caller of this is deciding which epoch a
// cache belongs to, and a bool is the one result shape a caller can ignore by not looking at it;
// the value that would then be bound is the attacker's.
//
// AN ERASED EPOCH IS REFUSED AS AN ERASE and not as a bad tag, which is Export's and
// ExternalKeyPair's convention and is the difference between two sentences a caller acts on
// differently. VerifyConfirmationTag would refuse it either way -- it asks secretIsLive first --
// so the check here is about what the caller is TOLD: "the tag does not confirm this context"
// sends a member looking for a fork with a peer, and the truth is that this client dropped the
// epoch's secrets when it aged out of PastEpochWindow. The liveness question is asked at the
// moment it is acted on rather than through a predicate, for the reason secretIsLive gives.
func (self *KeySchedule) ConfirmGroupContext(confirmationTag []byte) (*VerifiedGroupContext, error) {
	if !self.secretIsLive(self.secrets.Confirmation) {
		return nil, fmt.Errorf("%w: its confirmation key is zeros, which every party can compute, so nothing it accepted would be confirmed by anybody",
			ErrEpochErased)
	}
	decoded := &GroupContext{}
	if err := syntax.Unmarshal(self.groupContextBytes, decoded); err != nil {
		// the bytes this schedule expanded over were produced by marshalling a
		// GroupContext, so a refusal here is this build disagreeing with its own codec
		// rather than anything a peer did
		return nil, fmt.Errorf("mls: the schedule's own group context did not decode: %w", err)
	}
	if !self.VerifyConfirmationTag(decoded.ConfirmedTranscriptHash, confirmationTag) {
		return nil, fmt.Errorf("%w: epoch %d of group %x", errUnconfirmedGroupContext,
			decoded.Epoch, decoded.GroupId)
	}
	return &VerifiedGroupContext{inner: decoded}, nil
}
