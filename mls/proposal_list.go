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
	"errors"
	"fmt"
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
