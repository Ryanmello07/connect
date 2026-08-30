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

// The four refusals this gate answers, standing in for the validation plan's catalogue.
//
// One value per rule and never one value shared by two, which is errors_lifecycle.go's rule and
// the reason p8's catalogue spells them separately: a caller -- or a test -- asking which of the
// three unimplemented types it was handed cannot tell them apart when all three answer one value,
// and "a set of refusals that all reduce to one comparison" is this project's most repeated
// defect. errProfileExternalCommit rather than errProfileExternalInit is p8's spelling and is
// kept, because external_init is the proposal an external COMMIT carries and the refusal is about
// the commit shape rather than about one arm.
var (
	errProfilePsk              = errors.New("mls: pre_shared_key proposals are outside the v1 profile")
	errProfileReInit           = errors.New("mls: reinit proposals are outside the v1 profile")
	errProfileExternalCommit   = errors.New("mls: external commits are outside the v1 profile")
	errUnsupportedProposalType = errors.New("mls: proposal type is not one this build processes")
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
// never a legal proposal type, so the refusal it earns is the unsupported one.
var proposalTypeProfile = map[ProposalType]error{
	ProposalTypeReserved:               errUnsupportedProposalType,
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
// registered after this was written -- is refused as unsupported, because there is nothing to
// name. Both are refusals; a v1 client acts on four proposal types and no others.
func (self *profile) checkProposalType(proposalType ProposalType) error {
	refusal, registered := proposalTypeProfile[proposalType]
	if !registered {
		return fmt.Errorf("%w: %s is not a registered proposal type",
			errUnsupportedProposalType, proposalTypeName(proposalType))
	}
	if refusal != nil {
		return fmt.Errorf("%w: %s is registered and outside the v1 profile",
			refusal, proposalTypeName(proposalType))
	}
	return nil
}

// checkProposalProfile refuses any proposal this build will not process.
//
// Three rules, in the order a caller wants to hear them:
//
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
func checkProposalProfile(active *profile, proposal *Proposal) error {
	if proposal == nil {
		return fmt.Errorf("%w: nil proposal", errUnsupportedProposalType)
	}
	if active == nil {
		active = defaultProfile()
	}
	if err := active.checkProposalType(proposal.ProposalType); err != nil {
		return err
	}
	if proposal.UnknownType != ProposalTypeReserved {
		return fmt.Errorf("%w: %s would be encoded under the discriminant %s",
			errUnsupportedProposalType, proposalTypeName(proposal.ProposalType),
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

// ProposalCache holds the proposals received this epoch, keyed by ProposalRef.
//
// THE KEY IS THE WHOLE REFERENCE, converted to a string. Not a prefix of it, and not a
// comparison: a map over the full octets answers exactly the entry whose reference the commit
// named, and there is no comparator in the lookup at all -- which is how this stays out of the
// class guardrail 8's derived gate reads, rather than by picking a comparator off a list. A key
// cut short is a proposal SUBSTITUTION and not a missed lookup: two references sharing the
// truncated prefix answer the same entry, so a commit naming one member's removal applies
// another member's, under a reference every peer checks and agrees with.
//
// THE CACHE IS BOUND TO ONE EPOCH. groupId and epoch are taken from the first entry stored and
// every later Store is held to them, because a ProposalRef is a hash over an AuthenticatedContent
// that carries both -- so an entry from another epoch is not merely stale, it is a name no commit
// of THIS epoch can legitimately carry. Clear unbinds. What this cannot do on its own is notice
// that the epoch advanced with no proposal arriving in the new one, which is why CheckEpoch
// exists and why the commit path has to call it: see the note there.
type ProposalCache struct {
	byRef map[string]CachedProposal
	order []string
	// a COPY of the caller's group id and not the caller's own array. The cache outlives the
	// buffer a proposal was decoded out of, and a binding aliased to that buffer follows it
	// when the caller reuses it -- so the one guard that would say this cache had gone stale
	// would agree with whatever the buffer now holds.
	groupId []byte
	epoch   uint64
}

// NewProposalCache returns an empty cache, bound to no epoch.
func NewProposalCache() *ProposalCache {
	return &ProposalCache{byRef: map[string]CachedProposal{}}
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

// CheckEpoch refuses when this cache holds an epoch other than the one the caller is about to act
// in.
//
// It exists because Resolve cannot ask the question itself. Resolve is handed a committer and a
// ProposalOrRef vector and nothing that names an epoch, so the one place the cache sees an epoch
// is Store -- and a cache that was never cleared after a commit goes on answering the previous
// epoch's references to a commit of the new one, which is a REPLAY: a proposal a member published
// and the group already applied, applied a second time under a reference that still verifies.
// Store refuses an entry from another epoch, so the cache can only ever hold one epoch's worth;
// what Store cannot see is an epoch that advanced with no new proposal in it.
//
// The commit path is therefore expected to call this before Resolve and Clear on every epoch
// change. That is a rule about a CALLER and not one this type can enforce through a signature the
// group lifecycle plan pins -- said out loud here rather than left as a comment claiming a
// discipline nothing checks.
//
// An empty cache belongs to no epoch and answers nil: there is nothing in it to be stale.
func (self *ProposalCache) CheckEpoch(groupId []byte, epoch uint64) error {
	if len(self.byRef) == 0 {
		return nil
	}
	// crypto/subtle and not == over a string conversion. That is framing_protect.go's
	// CheckFramedContentContext one type up, comparing the same field for the same reason:
	// this package holds no comparison of octets spelled as ordinary go equality at all, and
	// TestFramingUsesConstantTimeComparison reads that off the type checked source rather than
	// off a list of comparator names -- so a string conversion is not a way around it, it is
	// the exact shape that gate was built after somebody tried.
	if subtle.ConstantTimeCompare(self.groupId, groupId) != 1 || self.epoch != epoch {
		return fmt.Errorf("%w: the cache holds epoch %d of group %x and was asked for epoch %d of group %x",
			errProposalCacheEpoch, self.epoch, self.groupId, epoch, groupId)
	}
	return nil
}

// Store caches a proposal received this epoch and answers its reference.
//
// The order of the refusals is the order a caller wants to hear them, and it is asserted rather
// than assumed. The PROVIDER first, because the reference is a hash and the hash is the
// provider's, so a body that judged the message first would answer "this is not a proposal" to a
// caller whose actual mistake was passing no provider. Then the message itself, then the SENDER,
// then the v1 profile, then the EPOCH -- and the reference is computed last, because it is the
// only step that costs a hash and there is nothing to hash in a message five rules have already
// refused.
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
func (self *ProposalCache) Store(crypto CryptoProvider, content *AuthenticatedContent) (ProposalRef, error) {
	if crypto == nil {
		return nil, fmt.Errorf("%w: the reference an entry is keyed by is a hash and the hash is the provider's", ErrNilCryptoProvider)
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
	if err := self.CheckEpoch(content.Content.GroupId, content.Content.Epoch); err != nil {
		return nil, err
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
	// nil map reads fine and only the insert below needs one.
	if self.byRef == nil {
		self.byRef = map[string]CachedProposal{}
	}
	self.groupId = bytes.Clone(content.Content.GroupId)
	self.epoch = content.Content.Epoch
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

// Get looks up a cached proposal by its whole reference.
//
// The value it answers is the cache's own and is not copied: Get has no error to report a copy
// failing with, and a copy on every lookup would be a marshal per resolved reference. A caller
// that writes into what it gets back corrupts the entry. Resolve, which is what the commit path
// actually uses, copies.
func (self *ProposalCache) Get(ref ProposalRef) (CachedProposal, bool) {
	cached, ok := self.byRef[string(ref)]
	return cached, ok
}

// Resolve turns a commit's ProposalOrRef vector into one bucketed list, so that validation and
// application have exactly one path whether the commit carried a proposal inline or by name.
//
// Four rules that are the cache's rather than validation's, in the order they are applied:
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
//  4. a second GroupContextExtensions proposal is refused, which is what makes
//     ProposalList.Extensions exact rather than a silent choice between two extension sets.
//
// The provider is not reached. It is in the signature because the group lifecycle plan pins it
// there and every caller already holds one; the refusal below is what stops the parameter being a
// promise the body does not keep.
func (self *ProposalCache) Resolve(crypto CryptoProvider, committer LeafIndex,
	refs []ProposalOrRef) (*ProposalList, error) {
	if crypto == nil {
		return nil, fmt.Errorf("%w: resolution runs under the caller's provider", ErrNilCryptoProvider)
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
			// reachable, and that is why it is here rather than argued away as dead. The
			// four cases above are the four types proposalTypeProfile classifies as
			// accepted, and a fifth accepted with no bucket beside it would otherwise be
			// counted in All and applied by nothing.
			// TestEveryProposalTypeTheV1ProfileAcceptsLandsInABucketOfItsOwn derives the
			// accepted set off that table and fails on the commit that widens it.
			return nil, fmt.Errorf("%w: %s has no bucket", errUnsupportedProposalType,
				proposalTypeName(cached.Proposal.ProposalType))
		}
	}
	return list, nil
}

// Pending answers every cached proposal as a by-reference entry, in the order it was received.
//
// A committer includes all valid pending proposals (RFC 9420 section 12.4 SHOULD), and the ORDER
// is the reception order rather than the map's, because Add placement depends on it and a map
// range answers a different tree on every run.
func (self *ProposalCache) Pending() []ProposalOrRef {
	out := make([]ProposalOrRef, 0, len(self.order))
	for _, key := range self.order {
		out = append(out, ProposalOrRef{Type: ProposalOrRefTypeReference, Reference: ProposalRef(key)})
	}
	return out
}

// Clear empties the cache and unbinds it from the epoch it was holding. Called on every epoch
// change, which is the discipline CheckEpoch exists to make observable.
func (self *ProposalCache) Clear() {
	self.byRef = map[string]CachedProposal{}
	self.order = nil
	self.groupId = nil
	self.epoch = 0
}
