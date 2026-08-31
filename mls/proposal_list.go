// The v1 profile gate for proposals, plus the two small type predicates the commit path needs.
// Spec A sections 3.1 and 3.2.
//
// RFC 9420 registers seven proposal types and the codec in proposal_wire.go decodes all of them
// plus an unregistered arm, because the `messages` vector family cannot be green otherwise and
// because a decoder that refused three of them would be the thing deciding policy. Refusing three
// is a PROFILE decision, so it lives here, at the boundary where a Proposal enters this plan's
// state -- the cache, resolution, and ValSem113 -- which is the difference between a message that
// is dropped and a message whose unimplemented arm is silently skipped.
//
// WHAT THIS FILE OWNS AND WHAT IT IS STANDING IN FOR. `Profile`, `DefaultProfile` and the seven
// `Check*` gates are the VALIDATION plan's (p8 section 9.3, connect/mls/profile.go), and that
// plan owns the single declaration site for each. None of them has landed. So the surface here is
// unexported and lowercase, the shape credential.go's errProfileCredentialType and
// key_package.go's errProfileCiphersuite already take: an exported Profile declared here would be
// a second public declaration site for a name p8 also declares, and the four refusals would be
// four error VALUES that no caller outside this package could match with errors.Is even after the
// real ones landed. Every consumer of this gate in the tasks after this one is inside package mls,
// so the swap costs nobody else anything -- when p8 lands profile.go, `profile` becomes `*Profile`,
// `defaultProfile()` becomes `DefaultProfile()`, `checkProposalType` is deleted in favour of
// `(*Profile).CheckProposalType`, and each err* below is replaced by its exported twin at every
// use. Those are all in-package, so the compiler finds every one of them in that commit, and
// TestNoValidationOwnedNameHasLandedBesideItsStandIn fails until the four errors are swapped.
package mls

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// The refusals this gate answers, standing in for the validation plan's catalogue.
//
// One value per rule and never one value shared by two, which is errors_lifecycle.go's rule and
// the reason p8's catalogue spells them separately: a caller -- or a test -- asking which of the
// three unimplemented types it was handed cannot tell them apart when all three answer one value,
// and "a set of refusals that all reduce to one comparison" is this project's most repeated
// defect. errProfileExternalCommit rather than errProfileExternalInit is p8's spelling and is
// kept, because external_init is the proposal an external COMMIT carries and the refusal is about
// the commit shape rather than about one arm.
//
// THE RULE ABOVE ONCE DID NOT HOLD IN THIS FILE, which is why the list is longer than the plan's
// four. Five rules of this gate -- a RESERVED code point, a code point OUTSIDE the registry, a
// NIL proposal, a wire DISCRIMINANT that is not the type the proposal names, and an accepted type
// resolution has no BUCKET for -- all answered one value whose message read "proposal type is not
// one this build processes". That is not a spelling question. This gate has two callers and they
// need opposite handling: ProposalCache.Store judges what a PEER sent, where "a code point this
// build does not implement" is routine traffic to drop, and Resolve judges what this build's own
// commit path ASSEMBLED, where a forged discriminant means this build is emitting proposals whose
// ProposalRef every receiver computes over octets naming a different type -- messages that will
// not verify, produced by us. A caller handed one value cannot separate the two, and the forged
// case was reported to it as a sentence about a registry, over a proposal whose type is
// registered and whose octets are the whole of what is wrong.
var (
	errProfilePsk            = errors.New("mls: pre_shared_key proposals are outside the v1 profile")
	errProfileReInit         = errors.New("mls: reinit proposals are outside the v1 profile")
	errProfileExternalCommit = errors.New("mls: external commits are outside the v1 profile")

	errReservedProposalType       = errors.New("mls: the reserved code point names no proposal")
	errUnregisteredProposalType   = errors.New("mls: proposal type is not in this build's proposal type registry")
	errNilProposal                = errors.New("mls: the v1 profile gate was handed no proposal")
	errForgedProposalDiscriminant = errors.New("mls: proposal would be encoded under a discriminant other than the type it names")
	errAcceptedTypeHasNoBucket    = errors.New("mls: the v1 profile accepts a proposal type resolution has no bucket for")
)

// proposalTypeProfile is the v1 disposition of every REGISTERED proposal type: nil for the four
// this build implements, and the sentinel that names why for the three it does not.
//
// A map keyed by the registry's own constants rather than a switch listing four accepted names,
// because the accepted set is the complement of a refused set and only one of the two can be
// written down without understating the other. What holds it to the registry is
// TestTheV1ProfileClassifiesEveryRegisteredProposalType, which reads the ProposalType constants
// out of this package's source and compares the two sets in BOTH directions: an eighth code point
// registered in extension.go with no row here fails, and a row here for a code point that no
// longer exists fails too. That is the shape rule 5 asks for -- the table is an enumeration only
// if nothing derives the class it is supposed to cover.
//
// ProposalTypeReserved is in the map and refused. It is a registry code point, so leaving it out
// would make the two sets unequal for a reason that has nothing to do with the profile, and it is
// never a legal proposal type -- which is a rule of its OWN and not the unregistered one. 0x0000
// IS in the registry; what it is registered as is "not a proposal", and a caller told "this code
// point is not in the registry" about it would go looking for a registration that is right there.
var proposalTypeProfile = map[ProposalType]error{
	ProposalTypeReserved:               errReservedProposalType,
	ProposalTypeAdd:                    nil,
	ProposalTypeUpdate:                 nil,
	ProposalTypeRemove:                 nil,
	ProposalTypePreSharedKey:           errProfilePsk,
	ProposalTypeReInit:                 errProfileReInit,
	ProposalTypeExternalInit:           errProfileExternalCommit,
	ProposalTypeGroupContextExtensions: nil,
}

// profile is the stand-in for the validation plan's Profile: the set of narrowings this build
// applies on top of RFC 9420.
//
// It carries no field yet because the only narrowing this task states is over proposal types, and
// a field nothing reads is a decision nobody made. p8's Profile carries AllowPublicMessage and
// the other six Check* gates; when it lands, this type is deleted rather than extended.
type profile struct{}

// defaultProfile is the v1 profile every caller in this plan runs under.
func defaultProfile() *profile {
	return &profile{}
}

// checkProposalType is the one refusal surface for a proposal type, standing in for
// (*Profile).CheckProposalType.
//
// The two answers it separates are worth separating: a REGISTERED type this profile does not
// implement is refused with the sentinel naming which one, so a peer running a fuller profile can
// be told what this build will not do, and an UNREGISTERED one -- a GREASE value, or a code point
// registered after this was written -- is refused with its own sentinel, because there is no
// narrowing to name and the remedy is a different one: a registered refusal is a decision this
// profile made and could revisit, an unregistered one is a code point nothing here has ever heard
// of. Both are refusals; a v1 client acts on four proposal types and no others.
func (self *profile) checkProposalType(proposalType ProposalType) error {
	refusal, registered := proposalTypeProfile[proposalType]
	if !registered {
		return fmt.Errorf("%w: %s is not a registered proposal type",
			errUnregisteredProposalType, proposalTypeName(proposalType))
	}
	if refusal != nil {
		return fmt.Errorf("%w: %s is registered and outside the v1 profile",
			refusal, proposalTypeName(proposalType))
	}
	return nil
}

// checkProposalProfile refuses any proposal this build will not process.
//
// Four rules, in the order a caller wants to hear them:
//
//  0. that there IS a proposal. A nil one has no type, no discriminant and no arm, so it is not
//     an unsupported type -- it is a caller that reached this gate holding nothing, which is a
//     commit path bug and not a message to drop. It answers its own value for that reason.
//  1. the TYPE, through the one refusal surface above;
//  2. the WIRE DISCRIMINANT, which is not always the type -- see below;
//  3. the ARM, through (*Proposal).checkArm, which is proposal_wire.go's and is not restated
//     here. The plan's own sketch wrote a second arm count in this file; that count is derived
//     off the Proposal struct by reflection in TestEveryArmOfAProposalIsCountedByItsArmCheck, and
//     a hand written copy of it beside the derived one is exactly the second implementation the
//     one-codec rule exists to prevent. The two would agree until an eighth arm was added, and
//     the copy that had not been updated would be the one this gate ran.
//
// Rule 2 is the one the plan does not have. Proposal.MarshalMLS puts UnknownType on the wire when
// it is set and selects the arm by ProposalType, which is deliberate -- it is how the validation
// plan's forge emits a well formed body under a GREASE code point without a second encoder
// existing. But it means the type this gate is asked about and the type the OCTETS carry can
// differ, and every ProposalRef, every transcript hash and every receiver's own gate run on the
// octets. A proposal admitted here as an Add and encoded under 0x0005 is a reference the proposer
// believes is an Add and every receiver refuses as a reinit. This plan never emits one, so it
// refuses to act on one.
//
// RULE 2 IS ABOUT THE DISAGREEMENT AND NOT ABOUT UnknownType BEING SET. The clause that landed
// read "UnknownType is set at all" while this comment and the clause's own test both said "the
// discriminant disagrees", so the file implemented one rule and documented another, and narrowing
// it to the documented one left the whole tree green.
//
// It left the tree green because the two readings differ over EXACTLY ONE input: an accepted type
// whose UnknownType equals it. Every other input is decided before this clause or by both
// readings alike -- a refused or unregistered type is answered by rule 1 above, and a genuine
// disagreement is refused either way -- and both fixtures in the clause's own test forge a
// genuine disagreement, so neither could tell the two apart. Which is also why the narrow rule
// costs the clause a backstop it used to have by accident: a decoded GREASE proposal carries
// UnknownType equal to ProposalType, because that is how proposal_wire.go makes GREASE round
// trip, so under the wide reading this clause refused one even with rule 1 switched off. Rule 1
// is the rule such a proposal breaks and is stated over all 65536 code points in a test of its
// own, and a second clause answering the same input with a different sentinel is not a backstop,
// it is two rules a caller cannot tell apart.
//
// That one input is what decides it. When the two are equal MarshalMLS writes the same
// discriminant it would write with UnknownType unset and selects the same arm, so the octets are
// byte for byte an ordinary add's: there is no second reading for any receiver to take, nothing
// about the value is wrong, and the refusal it earned read "add would be encoded under the
// discriminant add", which is not a sentence about a fault. The rule this clause exists for is
// octets carrying a type other than the one this gate judged, and the equal case carries the one
// it judged.
func checkProposalProfile(active *profile, proposal *Proposal) error {
	if proposal == nil {
		return fmt.Errorf("%w: nothing was handed to the type rule", errNilProposal)
	}
	if active == nil {
		active = defaultProfile()
	}
	if err := active.checkProposalType(proposal.ProposalType); err != nil {
		return err
	}
	if proposal.UnknownType != ProposalTypeReserved && proposal.UnknownType != proposal.ProposalType {
		return fmt.Errorf("%w: %s would be encoded under the discriminant %s",
			errForgedProposalDiscriminant, proposalTypeName(proposal.ProposalType),
			proposalTypeName(proposal.UnknownType))
	}
	return proposal.checkArm()
}

// proposalTypePathRequired is the RFC 9420 section 12.4 pathRequiredTypes set:
// [update, remove, external_init, group_context_extensions].
//
// It is stated over the whole registry rather than over the four this profile implements,
// because it is the RFC's rule and not this profile's: external_init is in the set and is refused
// by the gate above, and a predicate that answered false for it would be a wrong answer to a
// question about RFC 9420 that some later reader would take at face value. Which of the two rules
// a commit meets first is the caller's business.
func proposalTypePathRequired(proposalType ProposalType) bool {
	switch proposalType {
	case ProposalTypeUpdate, ProposalTypeRemove,
		ProposalTypeExternalInit, ProposalTypeGroupContextExtensions:
		return true
	}
	return false
}

// proposalTypeName names a type for an error message, in the RFC's own spelling.
//
// Deliberately not a String method on ProposalType: the registry enum is extension.go's and this
// plan does not extend it. The fallback names the code point in hex, because a refusal that said
// only "unsupported" would leave a caller diffing two captures to find out which value arrived.
func proposalTypeName(proposalType ProposalType) string {
	switch proposalType {
	case ProposalTypeReserved:
		return "reserved"
	case ProposalTypeAdd:
		return "add"
	case ProposalTypeUpdate:
		return "update"
	case ProposalTypeRemove:
		return "remove"
	case ProposalTypePreSharedKey:
		return "psk"
	case ProposalTypeReInit:
		return "reinit"
	case ProposalTypeExternalInit:
		return "external_init"
	case ProposalTypeGroupContextExtensions:
		return "group_context_extensions"
	}
	return fmt.Sprintf("proposal_type(%#04x)", uint16(proposalType))
}

// ---------------------------------------------------------------------------
// the per epoch proposal cache and commit resolution, RFC 9420 section 12.4
// ---------------------------------------------------------------------------

// What the cache refuses, one value per rule and never one value shared by two, which is
// errors_lifecycle.go's rule and the reason the four profile refusals above are spelled
// separately. A caller told only "the cache said no" cannot tell a reference it never published
// from a reference it published twice from one belonging to an epoch that has closed, and those
// are three different faults with three different remedies.
//
// THE EPOCH RULES ARE THREE VALUES for what a careless reading calls one rule, and they are three
// rules with three remedies. errProposalCacheEpoch is about a MESSAGE: a proposal arrived carrying
// an epoch other than the one the group is in, and the remedy is to drop it. The other two are
// about THIS BUILD, at two different doors. errProposalCacheNotRebound is Store's and CheckEpoch's:
// the cache is bound to an epoch the caller has already left, so the lifecycle advanced a group and
// did not Rebind, and the remedy is in the declaration that advanced it -- there is nothing wrong
// with any message. errProposalResolvedOutOfEpoch is Resolve's: the same staleness caught at the
// lookup, where what it costs is a commit naming proposals the group has already applied, so the
// refusal is a property of the resolution rather than a discipline expected of a caller.
//
// Three and not one because the audiences differ. A caller told only errProposalCacheEpoch cannot
// tell a peer that mislabelled one message from its own lifecycle failing to carry a whole cache
// across a boundary, and ledger 30 is four rules of this file sharing one value.
//
// Unexported, on the shape credential.go's errProfileCredentialType and this file's own
// errProfile* take, for two reasons that are not the same reason. errProposalSenderNotMember and
// errMultipleGroupContextExtensions stand in for names the VALIDATION plan owns -- section 12.2's
// "the sender of an Update is a member" is ValSem112 and "a list contains multiple
// GroupContextExtensions proposals" is one of that section's list rules -- and p7 task 7 declares
// ValSem112UpdateSenderIsMember as the named function those tests call, so an exported spelling
// here would be a second public declaration site for somebody else's rule.
// TestNoValidationOwnedNameHasLandedBesideItsStandIn watches every one of them for an exported
// twin. The other three are this cache's own invariants -- what a cache entry IS, what a
// reference NAMES, and which epoch it belongs to -- and they are unexported because nothing
// outside this package holds a ProposalCache.
var (
	errProposalCacheNotAProposal      = errors.New("mls: a cache entry must be a framed proposal")
	errProposalSenderNotMember        = errors.New("mls: a cached proposal is attributed to a leaf and only a member sender occupies one")
	errProposalCacheEpoch             = errors.New("mls: proposal does not belong to the epoch this cache holds")
	errProposalCacheNotRebound        = errors.New("mls: the proposal cache is bound to an epoch the caller has already left")
	errProposalResolvedOutOfEpoch     = errors.New("mls: a commit names a cached proposal from an epoch that has closed")
	errProposalNotCached              = errors.New("mls: proposal reference is not cached for this epoch")
	errDuplicateProposalReference     = errors.New("mls: a commit names one proposal reference twice")
	errMultipleGroupContextExtensions = errors.New("mls: a proposal list carries more than one group_context_extensions proposal")
)

// CachedProposal is a proposal plus the provenance validation needs: who sent it, and whether
// the commit carried it inline.
//
// Sender is a LEAF INDEX and not a Sender, which is what fixes the one rule Store has to enforce
// before anything else can. A leaf index attributed to a proposal whose sender was not a member
// is a number the sender never occupied, and ValSem111 -- the committer must not cover its own
// Update -- is then a comparison against a fabricated value. Task 7 re-checks the same property
// over a list assembled in process; this is the door every RECEIVED proposal comes through.
type CachedProposal struct {
	Ref      ProposalRef
	Proposal Proposal
	Sender   LeafIndex
	ByValue  bool
}

// ProposalList is one commit's proposals, bucketed by type and also kept in commit order.
//
// All is not a convenience. RFC 9420 section 12.1.1 places an added member at the leftmost blank
// leaf in the order the Add proposals appear, so two commits carrying the same set of adds in a
// different order build different trees -- and a bucket alone cannot say which order that was.
type ProposalList struct {
	Adds    []CachedProposal
	Updates []CachedProposal
	Removes []CachedProposal
	GCE     []CachedProposal
	All     []CachedProposal
}

// Len is the total proposal count.
func (self *ProposalList) Len() int {
	return len(self.All)
}

// PathRequired is the RFC 9420 section 12.4 rule: a commit carries an UpdatePath if its proposal
// list is EMPTY or contains any member of pathRequiredTypes.
//
// The empty half is the one that is easy to drop and is the one that matters most. A commit with
// no proposals and no path changes no key material at all, so the epoch advances over a secret
// every member of the previous epoch still holds -- which is the whole of what an update commit
// exists to prevent.
func (self *ProposalList) PathRequired() bool {
	if len(self.All) == 0 {
		return true
	}
	for _, cached := range self.All {
		if proposalTypePathRequired(cached.Proposal.ProposalType) {
			return true
		}
	}
	return false
}

// Extensions answers the replacement group context extensions when the list carries a
// GroupContextExtensions proposal.
//
// GCE[0], and not "the last one wins" or "the first one wins", because Resolve refuses a second
// one outright. RFC 9420 section 12.2 makes a list carrying two of them invalid, and a list that
// silently applied one of the two would be the group agreeing to an extension set no member can
// name. The index is therefore exact for every list this package produces. A ProposalList a
// caller assembled by hand can still hold two, and this answers the first of them -- see the note
// on errMultipleGroupContextExtensions.
//
// The hand assembled list is not a hypothetical and is why the index is held by a test of its
// own. Every list Resolve builds carries at most one GCE, so over those lists GCE[0] and
// GCE[len-1] are the same entry and no test that goes through Resolve can tell them apart --
// measured: the whole suite was green with the last one answered. p7 task 7 assembles
// ProposalList values field by field and reads this through
// (*ProposalValidationInput).effectiveExtensions, and there the two differ.
// TestExtensionsAnswersTheFirstOfTwoInAHandAssembledList is what separates them.
func (self *ProposalList) Extensions() ([]Extension, bool) {
	if len(self.GCE) == 0 {
		return nil, false
	}
	return self.GCE[0].Proposal.GroupContextExtensions.Extensions, true
}

// Refs rebuilds the ProposalOrRef vector a commit carries, in commit order.
func (self *ProposalList) Refs() []ProposalOrRef {
	out := make([]ProposalOrRef, 0, len(self.All))
	for i := range self.All {
		cached := self.All[i]
		if cached.ByValue {
			proposal := cached.Proposal
			out = append(out, ProposalOrRef{Type: ProposalOrRefTypeProposal, Proposal: &proposal})
			continue
		}
		out = append(out, ProposalOrRef{Type: ProposalOrRefTypeReference, Reference: cached.Ref})
	}
	return out
}

// proposalCacheBinding is the group and epoch one cache belongs to.
//
// A struct behind a POINTER, so that "bound to nothing" is a state this type can be in and can be
// told apart from "bound to the empty group at epoch 0" -- which is not a hypothetical, because
// epoch 0 is where every group starts and a zero valued pair would answer for it. A cache with no
// binding refuses at every door rather than acquiring one later, and that is the whole of what
// makes the zero value safe -- and the zero value is the only unbound cache there is, because the
// constructor refuses to build one.
//
// It is a type of its own rather than two fields of the cache so that the write has ONE target: a
// reader asking where the binding comes from reads the two places this struct is built, and
// TestEveryWriteOfTheCacheBindingReadsTheCallersGroupContext derives that class off the source
// rather than off this sentence.
type proposalCacheBinding struct {
	// a COPY of the caller's group id and not the caller's own array. The cache outlives the
	// buffer a group context was decoded out of, and a binding aliased to that buffer follows
	// it when the caller reuses it -- so the one guard that would say this cache had gone
	// stale would agree with whatever the buffer now holds.
	groupId []byte
	epoch   uint64
}

// ProposalCache holds the proposals received in ONE epoch of ONE group, keyed by ProposalRef.
//
// THE KEY IS THE WHOLE REFERENCE, converted to a string. Not a prefix of it, and not a
// comparison: a map over the full octets answers exactly the entry whose reference the commit
// named, and there is no comparator in the lookup at all -- which is how this stays out of the
// class guardrail 8's derived gate reads, rather than by picking a comparator off a list. A key
// cut short is a proposal SUBSTITUTION and not a missed lookup: two references sharing the
// truncated prefix answer the same entry, so a commit naming one member's removal applies
// another member's, under a reference every peer checks and agrees with.
//
// THE BINDING COMES FROM THE GROUP AND NEVER FROM A MESSAGE, and that is the whole design of this
// type. It is written in exactly two places -- NewProposalCache and Rebind -- and both read a
// *GroupContext the caller already holds; no method assigns it, so there is no code path in which
// a peer's octets decide which epoch this cache belongs to.
//
// It was the other way round, and the other way round is a denial of service, which is why this
// paragraph is here. The binding used to be taken from the first entry STORED and checked against
// that same entry's own epoch -- self referential for the first one -- and released only by a
// Clear the lifecycle had to remember. So one replayed genuine proposal of a closed epoch,
// delivered to a cache that had just been cleared, bound the cache to the closed epoch: the
// member could then neither cache the live epoch's proposals nor resolve any commit that named
// one, and nothing released it, because the only release ran off a commit the member could no
// longer resolve. Integrity held -- the stale proposal was never applied -- and availability was
// gone for good, at the cost of replaying one message every peer had already seen. A guard cannot
// fix that, because the value the guard compares against is the attacker's; only taking the value
// from somewhere else can, and the group's own context is the only other place it exists.
//
// What is left is a discipline of OURS rather than a door a peer can push: a lifecycle that
// advances an epoch and does not Rebind leaves this cache refusing the new epoch. That is a bug
// in this build, it is loud at every door, and it is derived rather than trusted --
// TestEveryDeclarationThatMovesAGroupToAnotherEpochEndsTheProposalCacheBinding reads the class of
// declarations that move a group between epochs off the source and holds every one of them to
// ending the binding.
type ProposalCache struct {
	byRef map[string]CachedProposal
	order []string
	// nil until the cache is bound. See proposalCacheBinding, and see bindingHolds for what
	// nil answers.
	binding *proposalCacheBinding
}

// NewProposalCache returns an empty cache bound to the group and epoch the CALLER is in.
//
// The context is a parameter rather than something the cache picks up later, because a cache that
// could be built without one has to learn its epoch from somewhere, and the only other thing on
// offer is whatever message arrives first. That is attacker supplied. Making the caller name the
// epoch is what turns "the cache checks that entries match" into "the cache knows which epoch it
// is in", and those are different claims: the first is true of a cache bound to a replay.
//
// A composite literal and not a field assignment, so that this constructor is not a second
// spelling of the write Rebind owns and a reader counting the places the binding is written
// counts two rather than three.
//
// IT REFUSES A NIL CONTEXT rather than answering a cache bound to nothing, and that is not a rule
// of this file: TestEveryConstructorOverAGroupContextRefusesANilOne derives the class of exported
// package level functions over a *GroupContext off this package's source and holds every one of
// them to ErrNilGroupContext. It is also the right rule here for a reason of this cache's own. A
// cache bound to nothing is the one state in which the epoch has to come from somewhere else, and
// a constructor that answered one would hand that state to every caller that did not read an
// error. The zero value is still that state -- Go's convention for a container leaves it usable --
// and it is safe for the reason bindingHolds gives: it refuses at every door.
func NewProposalCache(groupContext *GroupContext) (*ProposalCache, error) {
	if groupContext == nil {
		return nil, fmt.Errorf("%w: a cache is built bound to the epoch its group is in", ErrNilGroupContext)
	}
	return &ProposalCache{
		byRef: map[string]CachedProposal{},
		binding: &proposalCacheBinding{
			groupId: bytes.Clone(groupContext.GroupId),
			epoch:   groupContext.Epoch,
		},
	}, nil
}

// Rebind empties the cache and binds it to the group and epoch the caller names. It is what an
// epoch boundary owes this cache.
//
// One method for the two halves of a boundary -- release the closed epoch's entries, and take the
// new epoch -- because a cache that could be released WITHOUT being rebound is a cache in the
// unbound state again, and the unbound state is where binding-from-a-message used to be possible.
// This replaces the Clear that used to do only the first half, and the difference is not
// bookkeeping: Clear left behind exactly the state a replay could bind.
//
// It answers a refusal rather than binding to nothing when it is handed no context, for the same
// reason: the one thing a rebind must not be able to do is leave the cache with no epoch and a
// door open.
func (self *ProposalCache) Rebind(groupContext *GroupContext) error {
	if groupContext == nil {
		return fmt.Errorf("%w: a cache takes its epoch from the group's own context and from nothing else",
			ErrNilGroupContext)
	}
	self.byRef = map[string]CachedProposal{}
	self.order = nil
	self.binding = &proposalCacheBinding{
		groupId: bytes.Clone(groupContext.GroupId),
		epoch:   groupContext.Epoch,
	}
	return nil
}

// cloneProposal answers a copy of a proposal that shares no storage with the one it was handed,
// through the one codec rather than field by field.
//
// A hand written deep copy is a second traversal of a structure that already has one. It agrees
// with the codec until an eighth arm is added, and the arm the copy had not learned about would
// be silently dropped -- into a cache whose entire job is to answer what the group agreed to.
// Round tripping through Marshal and Unmarshal also makes the copy exactly what the octets say,
// which is the same thing the ProposalRef is a hash over.
//
// The caller's array is the reason this exists at all. A proposal arrives inside a buffer the
// caller decoded and still owns; a cache entry cut from that buffer changes underneath the group
// with no error path anywhere, and the commit resolved from it is one no peer can reproduce.
func cloneProposal(proposal *Proposal) (Proposal, error) {
	encoded, err := syntax.Marshal(proposal)
	if err != nil {
		return Proposal{}, err
	}
	copied := Proposal{}
	if err := syntax.Unmarshal(encoded, &copied); err != nil {
		return Proposal{}, err
	}
	return copied, nil
}

// bindingHolds answers whether the group and epoch this cache is bound to are the ones named.
//
// ONE comparison for the five rules that ask the question, because five copies of it are five
// places the wrong field can be compared and a reader mutating one would find the others still
// right. CheckEpoch, Store, Cached, Pending and Resolve all ask it; what they share is the question
// and not the answer, and each keeps its own refusal.
//
// AN UNBOUND CACHE ANSWERS FALSE, and there is no emptiness clause in front of it. An empty cache
// is not a cache that belongs to no epoch -- it belongs to the epoch it was bound to, and asking
// it about another one is the case CheckEpoch exists for: an epoch that advanced with no proposal
// arriving in the new one. The clause that used to short circuit on an empty map is exactly what
// made a freshly emptied cache answer nil for whatever epoch it was next asked about, and that is
// the door the binding used to walk in through.
//
// crypto/subtle and not == over a string conversion. That is framing_protect.go's
// CheckFramedContentContext one type up, comparing the same field for the same reason: this
// package holds no comparison of octets spelled as ordinary go equality at all, and
// TestFramingUsesConstantTimeComparison reads that off the type checked source rather than off a
// list of comparator names -- so a string conversion is not a way around it, it is the exact
// shape that gate was built after somebody tried.
//
// Both halves, and never the epoch alone: every group this client is a member of runs an epoch 7,
// so an epoch number is not an identity. And never the group alone: that is the whole of the
// replay this file exists to refuse.
func (self *ProposalCache) bindingHolds(groupId []byte, epoch uint64) bool {
	if self.binding == nil {
		return false
	}
	return subtle.ConstantTimeCompare(self.binding.groupId, groupId) == 1 && self.binding.epoch == epoch
}

// bindingName names what this cache belongs to, for a refusal a reader can act on.
//
// A cache bound to nothing says so rather than reporting "epoch 0 of group ", which is a sentence
// a reader would spend an afternoon looking for a group id in.
func (self *ProposalCache) bindingName() string {
	if self.binding == nil {
		return "no group"
	}
	return fmt.Sprintf("epoch %d of group %x", self.binding.epoch, self.binding.groupId)
}

// CheckEpoch refuses when this cache is bound to an epoch other than the one the caller is acting
// in.
//
// It is the boundary question asked without a message in hand: a lifecycle that has advanced an
// epoch and wants to know whether the cache came with it. That question is the one this file was
// rewritten around -- while the binding came from the first entry stored, an emptied cache
// answered nil for every epoch anybody asked about, so the guard could not see the case its own
// comment named.
//
// It is not the only thing standing between a closed epoch's proposals and a commit of the new
// one. Resolve asks the same question of its own group context, under
// errProposalResolvedOutOfEpoch, which is what makes the refusal a property of the RESOLUTION
// rather than a discipline expected of a caller -- see the note there. Both remain, because they
// answer for different callers: this one lets a lifecycle notice the boundary before it has
// anything to resolve, and the one in Resolve is the door no commit gets past.
func (self *ProposalCache) CheckEpoch(groupContext *GroupContext) error {
	if groupContext == nil {
		return fmt.Errorf("%w: the epoch a cache is checked against is the group's own",
			ErrNilGroupContext)
	}
	if !self.bindingHolds(groupContext.GroupId, groupContext.Epoch) {
		return fmt.Errorf("%w: the cache holds %s and the caller is acting in epoch %d of group %x",
			errProposalCacheNotRebound, self.bindingName(), groupContext.Epoch, groupContext.GroupId)
	}
	return nil
}

// checkResolveEpoch refuses a commit that names a cached reference while this cache belongs to
// another epoch.
//
// This is the replay door, and it is Resolve's own rule rather than CheckEpoch's. A ProposalRef
// is a hash over an AuthenticatedContent carrying the group id and the epoch, so an entry cached
// in epoch N is a name no commit of epoch N+1 can legitimately carry -- and a cache nobody
// rebound at the boundary answers exactly those names, which applies a proposal the group has
// already applied under a reference every peer still verifies.
//
// It is asked at the lookup rather than over the whole call, so a commit that carries every
// proposal INLINE is not refused for the state of a cache it never reads. What makes a reference
// a replay is that it names an entry, and this is the statement in front of the only line that
// can answer one.
func (self *ProposalCache) checkResolveEpoch(groupContext *GroupContext) error {
	if !self.bindingHolds(groupContext.GroupId, groupContext.Epoch) {
		return fmt.Errorf("%w: the cache holds %s and this commit is of epoch %d of group %x",
			errProposalResolvedOutOfEpoch, self.bindingName(),
			groupContext.Epoch, groupContext.GroupId)
	}
	return nil
}

// Store caches a proposal received in the caller's epoch and answers its reference.
//
// The order of the refusals is the order a caller wants to hear them, and it is asserted rather
// than assumed. The PROVIDER first, because the reference is a hash and the hash is the
// provider's, so a body that judged the message first would answer "this is not a proposal" to a
// caller whose actual mistake was passing no provider. Then the group CONTEXT, because it is the
// other thing the caller was asked for and it decides which epoch every rule below runs in. Then
// the message itself, then the SENDER, then the v1 profile. Then the two epoch rules, OURS first
// -- and the reference is computed last, because it is the only step that costs a hash and there
// is nothing to hash in a message seven rules have already refused.
//
// THE TWO EPOCH RULES ARE TWO RULES WITH TWO REMEDIES, and they are in that order because a stale
// cache makes every entry in it wrong while a mislabelled message is one message. CheckEpoch asks
// whether THIS CACHE came with the group -- a no means the lifecycle advanced an epoch and did
// not rebind, which is a bug in this build. The clause after it asks whether the MESSAGE belongs
// to the epoch the group is in -- a no means a peer sent, or somebody replayed, a proposal of
// another epoch, and the remedy is to drop it.
//
// The second rule is what it is because of what it is NOT: it does not compare the message
// against itself. The binding it is measured against was taken from the caller's group context at
// construction or at the last rebind, so a replayed proposal of a closed epoch is refused here
// and changes nothing -- not the entries, and above all not the binding, which this method does
// not write at all.
//
// The sender rule is this cache's own and is not ValSem112. A CachedProposal carries a LeafIndex,
// and a sender that is not a member has none: Sender{SenderType: SenderTypeNewMemberProposal}
// leaves the zero value in LeafIndex, so caching it would attribute somebody's external proposal
// to leaf 0 -- a real member, whose own Update would then read as the committer's under
// ValSem111. The v1 profile refuses external commits, so this build has no legitimate non member
// proposal to cache; a build that grew one would need a CachedProposal that can say "no leaf"
// rather than a wider gate here.
//
// The compiler directive is the package's convention for a member of the class
// TestEveryEraseHelperCarriesTheNoInlineDirective derives, and not a claim that this method
// erases a secret. That class is "writes through storage that outlives the call", read off the
// source; the insert below indexes into the receiver's own map, which is the shape, and tree.go's
// setNode carries the directive under the same reading and says so. Store is held to it because
// the derivation puts it there -- which is the point of deriving a class rather than listing one.
//
//go:noinline
func (self *ProposalCache) Store(crypto CryptoProvider, groupContext *GroupContext,
	content *AuthenticatedContent) (ProposalRef, error) {

	if crypto == nil {
		return nil, fmt.Errorf("%w: the reference an entry is keyed by is a hash and the hash is the provider's", ErrNilCryptoProvider)
	}
	if groupContext == nil {
		return nil, fmt.Errorf("%w: a store is refused unless it can name the epoch it is storing in", ErrNilGroupContext)
	}
	if content == nil {
		return nil, fmt.Errorf("%w: there is nothing to cache", errNilAuthenticatedContent)
	}
	if content.Content.ContentType != ContentTypeProposal || content.Content.Proposal == nil {
		return nil, fmt.Errorf("%w: content type %d", errProposalCacheNotAProposal, content.Content.ContentType)
	}
	if content.Content.Sender.SenderType != SenderTypeMember {
		return nil, fmt.Errorf("%w: sender type %d", errProposalSenderNotMember, content.Content.Sender.SenderType)
	}
	if err := checkProposalProfile(defaultProfile(), content.Content.Proposal); err != nil {
		return nil, err
	}
	// ours before theirs: a cache that did not come with the group is wrong about every entry
	// it holds, and a caller told only that one message was stale would go looking at the
	// message.
	if err := self.CheckEpoch(groupContext); err != nil {
		return nil, err
	}
	if !self.bindingHolds(content.Content.GroupId, content.Content.Epoch) {
		return nil, fmt.Errorf("%w: the proposal is of epoch %d of group %x and the cache holds %s",
			errProposalCacheEpoch, content.Content.Epoch, content.Content.GroupId, self.bindingName())
	}
	ref, err := content.ProposalRef(crypto)
	if err != nil {
		return nil, err
	}
	proposal, err := cloneProposal(content.Content.Proposal)
	if err != nil {
		return nil, err
	}
	// the zero valued cache is usable, which is Go's convention for a container and is what
	// lets the nil provider gate drive this method on a receiver it did not have to build. A
	// nil map reads fine and only the insert below needs one. It is not a way in: a zero
	// valued cache is bound to nothing, and the two rules above have already refused.
	if self.byRef == nil {
		self.byRef = map[string]CachedProposal{}
	}
	key := string(ref)
	if _, exists := self.byRef[key]; !exists {
		self.order = append(self.order, key)
	}
	// the entry's own Ref is cut from the KEY rather than from the answer, so the reference
	// this cache holds and the reference the caller walks away with share no storage. Storing
	// the caller's array back would let a caller that wrote into what Store returned change the
	// name of an entry it no longer owns.
	self.byRef[key] = CachedProposal{
		Ref:      ProposalRef(key),
		Proposal: proposal,
		Sender:   content.Content.Sender.LeafIndex,
		ByValue:  false,
	}
	return ref, nil
}

// Cached looks up a proposal of the caller's epoch by its whole reference.
//
// NOT SPELLED Get, AND THE NAME IS LOAD BEARING. tree.go declares (*RatchetTree).Get, and
// guardrail 8's reachability walk over the ratchet tree's key questions -- tree_test.go's
// TestEveryKeyQuestionOverTheRatchetTreeIsAnsweredInConstantTime -- is keyed by the bare
// declaration NAME, because it reads parsed source with no type information in it. Two methods
// called Get are one node in that graph. So a lookup here spelled Get would put this body's
// constant time comparison inside the call graph of every tree method that reads a node, which
// makes an excused member of that class read as reaching the sanctioned comparison -- measured,
// that is exactly what happened -- and, worse, makes the POSITIVE half of that rule satisfiable by
// any key question that happens to call something named Get. The rename keeps that gate as precise
// as it was rather than working around it.
//
// THE GROUP CONTEXT IS NOT DECORATION HERE. p7's CheckErrata8815 reads this and reports "proposal
// reference %x is not cached for this epoch" on a miss, and a Get that consulted only the map
// could not make that claim: it would answer an entry of a closed epoch to a caller that had
// asked about the live one. The ordering that saves it today -- Resolve running first at both
// call sites -- is a property of two call sites and not of this method, and those are different
// claims.
//
// A missing entry and an entry of another epoch are ONE answer, because to the caller they are
// one fact: nothing of your epoch is cached under that reference. A caller that needs the two
// apart is resolving a commit, and Resolve separates them under two sentinels of its own.
//
// The value it answers is the cache's own and is not copied: this has no error to report a copy
// failing with, and a copy on every lookup would be a marshal per resolved reference. A caller
// that writes into what it gets back corrupts the entry. Resolve, which is what the commit path
// actually uses, copies.
func (self *ProposalCache) Cached(groupContext *GroupContext, ref ProposalRef) (CachedProposal, bool) {
	if groupContext == nil {
		return CachedProposal{}, false
	}
	if !self.bindingHolds(groupContext.GroupId, groupContext.Epoch) {
		return CachedProposal{}, false
	}
	cached, ok := self.byRef[string(ref)]
	return cached, ok
}

// Resolve turns a commit's ProposalOrRef vector into one bucketed list, so that validation and
// application have exactly one path whether the commit carried a proposal inline or by name.
//
// Five rules that are the cache's rather than validation's, in the order they are applied:
//
//  1. every entry goes through ProposalOrRef.checkArm first, which is proposal_wire.go's and is
//     not restated here. It refuses a discriminant outside the two the registry defines, an entry
//     carrying both arms, and a reference of no octets -- the last of which would otherwise be a
//     lookup on the empty key that every commit making the same mistake shares.
//  2. a by-value proposal is attributed to the COMMITTER and a by-reference one keeps the sender
//     that cached it. That is the whole of what makes ValSem111 checkable: a committer whose own
//     Update could be read as somebody else's would be covering the one update RFC 9420
//     section 12.4 says its UpdatePath replaces.
//  3. a reference named TWICE is refused. RFC 9420 section 12.2 invalidates every list a
//     duplicate could produce -- two removes of one leaf, two adds of one client, two
//     GroupContextExtensions -- but those are task 7's rules over a list, and this one is about
//     identity: a reference IS a name, and one name resolving to two entries of one list means a
//     member's single published proposal is applied twice.
//  4. a reference into a cache bound to ANOTHER epoch is refused, under this cache's own
//     errProposalResolvedOutOfEpoch and not under Store's errProposalCacheEpoch -- see
//     checkResolveEpoch, and see the note beside the values for why the epoch rules are three.
//  5. a second GroupContextExtensions proposal is refused, which is what makes
//     ProposalList.Extensions exact rather than a silent choice between two extension sets.
//
// THE GROUP CONTEXT IS WHY RULE 4 CAN BE STATED AT ALL, and it is what this signature was
// changed to carry. The shape the group lifecycle plan first pinned took a committer and a
// vector and nothing that names an epoch, so this body could not ask which epoch it was
// resolving in -- and a proposal cached in epoch N therefore resolved in epoch N+1
// unconditionally, which is the one direction a cache must not fail. A group context is what
// every caller of this method already holds -- Commit and the inbound commit path both resolve
// against self.context -- so asking for it costs the callers nothing and moves the refusal from a
// discipline to a door.
//
// It is the same object the binding itself comes from, which is the second half of the fix and
// the more important one. Rule 4 was landed first, over a binding still taken from the first
// entry stored; that made a stale entry unusable but left the binding attacker supplied, so a
// replay of one genuine old proposal into a freshly emptied cache locked the member out of its
// own live epoch. A door is worth what the value behind it is worth.
//
// The provider is not reached. It is in the signature because the group lifecycle plan pins it
// there and every caller already holds one; the refusal below is what stops the parameter being a
// promise the body does not keep. The group context is reached, at rule 4, which is the
// difference between the two parameters and the reason only one of them needs that excuse.
func (self *ProposalCache) Resolve(crypto CryptoProvider, groupContext *GroupContext,
	committer LeafIndex, refs []ProposalOrRef) (*ProposalList, error) {
	if crypto == nil {
		return nil, fmt.Errorf("%w: resolution runs under the caller's provider", ErrNilCryptoProvider)
	}
	// before the vector is walked, because a resolution with no epoch to observe is the defect
	// this parameter was added to close and answering it per entry would make an empty commit
	// the one call that still has none.
	if groupContext == nil {
		return nil, fmt.Errorf("%w: resolution is refused unless it can name the epoch it runs in", ErrNilGroupContext)
	}
	list := &ProposalList{}
	namedAt := map[string]int{}
	for i := range refs {
		entry := refs[i]
		if err := entry.checkArm(); err != nil {
			return nil, fmt.Errorf("%w: at proposal_or_ref %d", err, i)
		}
		// the source proposal, the sender it is attributed to and the name it was resolved
		// under, decided before either is judged so that the profile gate below runs once
		// over both arms rather than once per branch.
		var source *Proposal
		var sender LeafIndex
		var name ProposalRef
		byValue := entry.Type == ProposalOrRefTypeProposal
		if byValue {
			// checkArm has already refused every type that is not one of the two, and
			// refused a nil Proposal arm under this one, so there is no third branch here
			// and no dereference to guard.
			source = entry.Proposal
			sender = committer
		} else {
			// the epoch BEFORE the lookup and before the duplicate bookkeeping. A cache
			// belonging to a closed epoch still answers every key it holds, so the lookup
			// below succeeds on a replayed reference and reports nothing; and a stale cache
			// makes every reference of this vector wrong, which is a larger fault than one
			// of them being named twice.
			if err := self.checkResolveEpoch(groupContext); err != nil {
				return nil, fmt.Errorf("%w: at proposal_or_ref %d", err, i)
			}
			key := string(entry.Reference)
			if at, twice := namedAt[key]; twice {
				return nil, fmt.Errorf("%w: entries %d and %d both name %x",
					errDuplicateProposalReference, at, i, entry.Reference)
			}
			namedAt[key] = i
			found, ok := self.byRef[key]
			if !ok {
				return nil, fmt.Errorf("%w: %x", errProposalNotCached, entry.Reference)
			}
			// a copy of the map's value, so the pointer below is to this loop's own
			// header rather than to the cache's; what it POINTS AT is still the cache's,
			// which is what the clone two statements down is for.
			source = &found.Proposal
			sender = found.Sender
			name = ProposalRef(key)
		}
		// the profile BEFORE the copy, and that order is load bearing rather than tidy. The
		// copy runs through the codec, and the codec refuses the arms of the three types v1
		// does not implement for reasons of its own -- a psk with no usage, a reinit with no
		// group id -- so a copy taken first answers whichever encoding rule the arm happened
		// to break instead of naming the profile rule that actually refused it. A by-value
		// proposal has been through no gate at all before this line, and an entry cached
		// under an earlier profile is judged here under the one running now.
		if err := checkProposalProfile(defaultProfile(), source); err != nil {
			return nil, err
		}
		proposal, err := cloneProposal(source)
		if err != nil {
			return nil, err
		}
		cached := CachedProposal{Ref: name, Proposal: proposal, Sender: sender, ByValue: byValue}
		list.All = append(list.All, cached)
		switch cached.Proposal.ProposalType {
		case ProposalTypeAdd:
			list.Adds = append(list.Adds, cached)
		case ProposalTypeUpdate:
			list.Updates = append(list.Updates, cached)
		case ProposalTypeRemove:
			list.Removes = append(list.Removes, cached)
		case ProposalTypeGroupContextExtensions:
			if len(list.GCE) != 0 {
				return nil, fmt.Errorf("%w: at proposal_or_ref %d", errMultipleGroupContextExtensions, i)
			}
			list.GCE = append(list.GCE, cached)
		default:
			// UNREACHABLE TODAY, and the account this branch used to carry -- "reachable,
			// and that is why it is here rather than argued away as dead" -- was false.
			// Every value reaching this switch has been through checkProposalProfile, which
			// refuses every type proposalTypeProfile does not classify as accepted, and the
			// four cases above are exactly the four it does. Nothing this build can assemble
			// arrives here. A justification comment is a claim, and that one could not be
			// checked by anybody who did not re-derive it.
			//
			// It stays, and it REFUSES rather than dropping, because the commit that widens
			// the accepted set is what makes it reachable: a fifth accepted type with no
			// bucket beside it would be counted in All, applied by nothing, and named by no
			// error -- a proposal the group agreed to and no member acted on.
			// TestEveryProposalTypeTheV1ProfileAcceptsLandsInABucketOfItsOwn fails on that
			// commit before this line ever runs, and
			// TestABucketlessAcceptedTypeIsRefusedRatherThanSilentlyDropped performs the
			// widening for the length of one test so that this line is executed rather than
			// reasoned about.
			return nil, fmt.Errorf("%w: %s has no bucket", errAcceptedTypeHasNoBucket,
				proposalTypeName(cached.Proposal.ProposalType))
		}
	}
	return list, nil
}

// Pending answers every proposal cached in the caller's epoch as a by-reference entry, in the
// order it was received.
//
// A committer includes all valid pending proposals (RFC 9420 section 12.4 SHOULD), and the ORDER
// is the reception order rather than the map's, because Add placement depends on it and a map
// range answers a different tree on every run.
//
// The group context is here for Cached's reason and it matters more here, because what this answers
// goes straight into a commit: a Pending that read only the map would hand a committer of the new
// epoch the references of the closed one, and the commit built from them names proposals no
// receiver can resolve. Nothing of another epoch is answered, so a committer over a cache nobody
// rebound commits nothing rather than committing a replay.
func (self *ProposalCache) Pending(groupContext *GroupContext) []ProposalOrRef {
	if groupContext == nil || !self.bindingHolds(groupContext.GroupId, groupContext.Epoch) {
		return []ProposalOrRef{}
	}
	out := make([]ProposalOrRef, 0, len(self.order))
	for _, key := range self.order {
		out = append(out, ProposalOrRef{Type: ProposalOrRefTypeReference, Reference: ProposalRef(key)})
	}
	return out
}
