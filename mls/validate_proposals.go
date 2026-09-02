// RFC 9420 section 12.2 proposal-list validation, one named function per ValSem code so the
// negative tests the validation plan owns have a specific target, plus the three list rules
// section 12.2 states with no code of their own. Every rule runs on the sender side and on the
// receiver side, from the same input.
//
// THE ORDER THE RULES RUN IN, and the one place it is not the plan's. ValSem113 runs FIRST rather
// than thirteenth, and the two structural rules beside it run before every ValSem code. That is
// not a preference about which refusal a caller sees: every rule below reads an ARM off a
// proposal -- cached.Proposal.Add.KeyPackage, cached.Proposal.Remove.Removed,
// cached.Proposal.Update.LeafNode -- and the check that an Add carries an Add arm lives inside
// ValSem113's gate, while the check that the Adds bucket carries only Adds lives beside it. Run
// thirteenth, as the plan writes it, a list holding an Add with a nil Add arm, or holding a
// Remove in the Adds bucket, is a nil dereference inside ValSem101 -- a panic out of a library,
// which takes the caller's process rather than its call. Every list (*ProposalCache).Resolve
// produces satisfies both preconditions; a ProposalList a caller assembled field by field, which
// is exactly what this plan's own tests and the vector runners build, satisfies neither.
//
// What that costs is a list failing both a structural rule and a duplicate-key rule reporting the
// structural one, and what it buys is that the other twelve rules can be written the way the RFC
// states them. Among the twelve themselves the plan's order stands: a duplicate key is reported
// before a capability mismatch, so the error a caller sees names the closest cause.
package mls

import (
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/urnetwork/connect/mls/syntax"
)

// ProposalValidationInput is the pre-commit state a proposal list is judged against.
//
// Extensions is the POST-GroupContextExtensions extension list, because RFC 9420 section 12.3
// applies the GCE proposal first and requires the new extensions to be used when evaluating the
// rest of the list: a GCE that adds a required_capabilities extension is a requirement every Add
// in the same commit has to meet. A caller that has already applied the list hands the applied
// set here; a caller that has not leaves it nil and effectiveExtensions derives it.
type ProposalValidationInput struct {
	Crypto     CryptoProvider
	Tree       *RatchetTree
	Context    *GroupContext
	Extensions []Extension
	Committer  LeafIndex
	List       *ProposalList
	Now        time.Time
}

// check is the argument rule every entry point of this file runs first.
//
// A method with a nil-receiver guard rather than a nil comparison in each of the fourteen
// functions, so that one rule is written once: fourteen copies of a guard is fourteen chances for
// one of them to be the copy that was not updated. Go calls a method on a nil pointer without
// dereferencing it, so this is reachable from every door.
// TestEveryProposalValidationEntryPointRefusesANilInput drives all fourteen.
func (self *ProposalValidationInput) check() error {
	if self == nil {
		return fmt.Errorf("%w: no validation input", errNilProposalValidationInput)
	}
	if self.List == nil {
		return fmt.Errorf("%w: no proposal list", errNilProposalValidationInput)
	}
	if self.Tree == nil {
		return fmt.Errorf("%w: no ratchet tree", errNilProposalValidationInput)
	}
	if self.Context == nil {
		return fmt.Errorf("%w: no group context", errNilProposalValidationInput)
	}
	return nil
}

// effectiveExtensions is the extension list the rest of the list is judged against.
//
// Three sources in one order, and each of the two fallbacks answers a caller that exists. An
// explicit Extensions is a caller that has already applied section 12.3's first step and is
// re-checking the applied state. A list carrying a GroupContextExtensions proposal is the sender
// side, which judges the list before applying anything. Neither is the ordinary case, which is
// the group's own extensions, unchanged.
func (self *ProposalValidationInput) effectiveExtensions() []Extension {
	if self.Extensions != nil {
		return self.Extensions
	}
	if exts, ok := self.List.Extensions(); ok {
		return exts
	}
	return self.Context.Extensions
}

// The three groups of rules ValidateProposalList runs, in the order it runs them.
//
// Slices rather than a straight-line sequence of calls, because what has to be checkable is that
// the aggregate runs EVERY ValSem code and not a subset of them:
// TestValidateProposalListRunsEveryValSemThisFileDeclares reads the ValSem function names out of
// this file's source and requires each to appear in exactly one of the three, so a fourteenth
// code added below is unrun until somebody puts it in a group, and a code deleted from a group
// fails rather than quietly leaving the aggregate smaller.
//
// The groups are three and not one because the ORDER between them is load bearing and the header
// says why: the structural group is what makes the other twelve safe to write.
var (
	proposalListStructuralChecks = []func(*ProposalValidationInput) error{
		ValSem113ProposalTypeSupported,
		validateProposalBucketsHoldTheirOwnType,
		validateBucketsAgreeWithTheCommitOrder,
		validateOneGroupContextExtensions,
		validateNoRepeatedProposalReference,
	}
	proposalListChecks = []func(*ProposalValidationInput) error{
		ValSem101UniqueSignatureKey,
		ValSem102UniqueInitKey,
		ValSem103UniqueEncryptionKey,
		ValSem104InitNotEqualEncryptionKey,
		ValSem105SuiteAndVersionMatch,
		ValSem106RequiredCapabilitiesSatisfied,
		ValSem107UniqueRemove,
		ValSem108RemoveExists,
		ValSem109UpdateRequiredCapabilities,
		ValSem110UpdateUniqueEncryptionKey,
		ValSem111NoCommitterUpdate,
		ValSem112UpdateSenderIsMember,
	}
	proposalListCrossChecks = []func(*ProposalValidationInput) error{
		validateSingleUpdateOrRemovePerLeaf,
		validateCommitterIsNotRemoved,
	}
)

// ValidateProposalList runs every rule of RFC 9420 section 12.2 over a regular, non-external
// commit's proposal list and returns the first failure.
//
// EXTERNAL COMMITS ARE NOT JUDGED HERE and that is a profile decision rather than a gap. Section
// 12.2 states a second, disjoint list of rules for a list carrying an ExternalInit, and this
// build refuses external commits outright at the profile gate -- errProfileExternalCommit -- so
// an external commit's list is refused by ValSem113 before any rule below could be asked about
// it. A second procedure here would be an implementation of a shape this build never accepts.
func ValidateProposalList(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	for _, group := range [][]func(*ProposalValidationInput) error{
		proposalListStructuralChecks, proposalListChecks, proposalListCrossChecks} {
		for _, check := range group {
			if err := check(in); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// the structural rules the twelve below are written against
// ---------------------------------------------------------------------------

// proposalBucket is one of a ProposalList's per-type buckets: the field it is held in, the type
// every entry of it must carry, and the entries.
type proposalBucket struct {
	field   string
	carries ProposalType
	entries []CachedProposal
}

// proposalBucketsOf is every per-type bucket of a list, and it is the one place they are
// enumerated.
//
// A list of four fields is exactly the shape rule 5 warns about, so it is held to the type rather
// than to memory: TestEveryBucketOfAProposalListIsNamedByTheBucketRule reflects over
// ProposalList's own fields and requires every []CachedProposal field except the commit-order one
// to appear here. A fifth bucket added to the struct by a later task -- a psk bucket, when the
// profile widens -- fails that test rather than silently sitting outside every rule below.
func proposalBucketsOf(list *ProposalList) []proposalBucket {
	return []proposalBucket{
		{field: "Adds", carries: ProposalTypeAdd, entries: list.Adds},
		{field: "Updates", carries: ProposalTypeUpdate, entries: list.Updates},
		{field: "Removes", carries: ProposalTypeRemove, entries: list.Removes},
		{field: "GCE", carries: ProposalTypeGroupContextExtensions, entries: list.GCE},
	}
}

// ValSem113ProposalTypeSupported: every proposal in the list is one this group can process.
//
// It reaches the same gate (*ProposalCache).Store and (*ProposalCache).Resolve reach, which is
// what keeps exactly one table of what the v1 profile accepts. Its answers are that gate's eight
// values unchanged and not an umbrella of this file's own -- see the note in
// errors_proposal_validation.go.
//
// The sweep is over the commit order AND over every bucket, which is not redundant on a list a
// caller assembled: All and the buckets are separate fields, nothing makes one a permutation of
// the other, and a proposal reachable by application through a bucket while absent from All would
// otherwise be applied by ApplyProposals having been judged by nothing. It is also what makes the
// twelve rules below safe to write, because the arm check is inside this gate.
func ValSem113ProposalTypeSupported(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	active := defaultProfile()
	for i := range in.List.All {
		if err := checkProposalProfile(active, &in.List.All[i].Proposal); err != nil {
			return fmt.Errorf("%w: at proposal %d of the commit order", err, i)
		}
	}
	for _, bucket := range proposalBucketsOf(in.List) {
		for i := range bucket.entries {
			if err := checkProposalProfile(active, &bucket.entries[i].Proposal); err != nil {
				return fmt.Errorf("%w: at %s[%d]", err, bucket.field, i)
			}
		}
	}
	return nil
}

// validateProposalBucketsHoldTheirOwnType is the precondition every bucketed rule below reads
// against: an entry of the Removes bucket is a Remove.
//
// (*ProposalCache).Resolve buckets by the proposal's own type, so nothing this package assembles
// can fail this. What can is a ProposalList built field by field -- the shape the vector runners
// and every test of this file build -- and the failure mode is not a wrong answer but a nil
// dereference two rules later.
func validateProposalBucketsHoldTheirOwnType(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	for _, bucket := range proposalBucketsOf(in.List) {
		for i := range bucket.entries {
			if got := bucket.entries[i].Proposal.ProposalType; got != bucket.carries {
				return fmt.Errorf("%w: %s[%d] is a %s", ErrProposalListMisbucketed,
					bucket.field, i, proposalTypeName(got))
			}
		}
	}
	return nil
}

// validateBucketsAgreeWithTheCommitOrder holds a list's buckets to its commit order by count.
//
// Every entry (*ProposalCache).Resolve produces is appended to All and to exactly one bucket in
// the same statement list, so nothing this package resolves can fail this. What can is a list a
// caller assembled field by field, and the failure it closes is the quiet one: ApplyProposals
// walks All to place Adds in commit order while every rule of this file reads the Adds bucket, so
// a list carrying its adds in one field and not the other is judged by validation and applied by
// nothing, or applied without ever having been judged. Both are green suites.
//
// A count and not an identity, said plainly: two entries of one type in All and two in the bucket
// satisfy this even if they are four different proposals. That shape is a caller assembling a
// value inconsistently on purpose, and the cost of catching it -- encoding every proposal twice
// to compare -- is not worth paying on a path a commit runs.
func validateBucketsAgreeWithTheCommitOrder(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	inOrder := map[ProposalType]int{}
	for i := range in.List.All {
		inOrder[in.List.All[i].Proposal.ProposalType] += 1
	}
	for _, bucket := range proposalBucketsOf(in.List) {
		if got, want := len(bucket.entries), inOrder[bucket.carries]; got != want {
			return fmt.Errorf("%w: %s holds %d and the commit order carries %d %s proposals",
				ErrProposalListBucketsDisagree, bucket.field, got, want,
				proposalTypeName(bucket.carries))
		}
	}
	return nil
}

// validateOneGroupContextExtensions is RFC 9420 section 12.2's "It contains multiple
// GroupContextExtensions proposals".
//
// The cache's Resolve refuses the second one as it buckets, under this same value; this is the
// other door, for a list nothing resolved. It is what makes ProposalList.Extensions exact rather
// than a silent choice between two extension sets, and it runs before ValSem106 and ValSem109
// because both of those read the answer.
func validateOneGroupContextExtensions(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	if len(in.List.GCE) > 1 {
		return fmt.Errorf("%w: the list carries %d", errMultipleGroupContextExtensions, len(in.List.GCE))
	}
	return nil
}

// validateNoRepeatedProposalReference refuses a commit that names one cached proposal twice.
//
// Resolve refuses it as it walks the ProposalOrRef vector, and this is the same rule over a list
// that vector no longer exists for. It is NOT covered by the duplicate rules below and that is
// the whole reason it is written: two references to one Remove are caught by ValSem107, two to
// one Add by ValSem101, two to one Update by the same-leaf rule -- but each of those is a rule
// about the CONTENT, and a duplicate reference is a fault about IDENTITY. A profile that later
// admits a fifth proposal type would have to add a content rule for it or lose the refusal
// entirely, and the RFC's own transcript is computed over the vector rather than over its
// contents.
//
// By-value entries carry no reference and are skipped: their Ref is the zero value, and a list of
// two inline proposals would otherwise be two entries sharing the empty name.
func validateNoRepeatedProposalReference(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	namedAt := map[string]int{}
	for i := range in.List.All {
		cached := in.List.All[i]
		if cached.ByValue || len(cached.Ref) == 0 {
			continue
		}
		key := string(cached.Ref)
		if at, twice := namedAt[key]; twice {
			return fmt.Errorf("%w: entries %d and %d both name %x",
				errDuplicateProposalReference, at, i, cached.Ref)
		}
		namedAt[key] = i
	}
	return nil
}

// ---------------------------------------------------------------------------
// ValSem101 to ValSem112
// ---------------------------------------------------------------------------

// ValSem101UniqueSignatureKey: an Add's signature key is unique among the proposals and among the
// members this commit leaves in the group.
//
// The members' half excludes leaves this list removes, which is RFC 9420 section 12.2's "unless
// there is a Remove proposal in the list removing the matching client from the group" -- the
// clause that makes a device replacing itself in one commit legal.
func ValSem101UniqueSignatureKey(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	seen := map[string]bool{}
	removed := removedLeaves(in.List)
	for _, leafIndex := range in.Tree.NonBlankLeaves() {
		if removed[leafIndex] {
			continue
		}
		leaf := in.Tree.Leaf(leafIndex)
		if leaf == nil {
			continue
		}
		seen[string(leaf.SignatureKey)] = true
	}
	for i := range in.List.Adds {
		key := string(in.List.Adds[i].Proposal.Add.KeyPackage.LeafNode.SignatureKey)
		if seen[key] {
			return fmt.Errorf("%w: adds[%d] publishes %x", ErrAddDuplicateSignatureKey, i, key)
		}
		seen[key] = true
	}
	return nil
}

// ValSem102UniqueInitKey: an Add's init key is unique among the proposals.
//
// Among the proposals only. An init key belongs to a KeyPackage and a KeyPackage is consumed by
// the Welcome; nothing in the ratchet tree publishes one, so there is no members' half to check
// and a loop over the tree here would be enforcing a rule over values it could not read.
func ValSem102UniqueInitKey(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for i := range in.List.Adds {
		key := string(in.List.Adds[i].Proposal.Add.KeyPackage.InitKey)
		if seen[key] {
			return fmt.Errorf("%w: adds[%d] publishes %x", ErrDuplicateInitKey, i, key)
		}
		seen[key] = true
	}
	return nil
}

// ValSem103UniqueEncryptionKey: an Add's leaf encryption key is unique among the proposals and
// among the members this commit leaves in the group.
func ValSem103UniqueEncryptionKey(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	seen := map[string]bool{}
	removed := removedLeaves(in.List)
	for _, leafIndex := range in.Tree.NonBlankLeaves() {
		if removed[leafIndex] {
			continue
		}
		leaf := in.Tree.Leaf(leafIndex)
		if leaf == nil {
			continue
		}
		seen[string(leaf.EncryptionKey)] = true
	}
	for i := range in.List.Adds {
		key := string(in.List.Adds[i].Proposal.Add.KeyPackage.LeafNode.EncryptionKey)
		if seen[key] {
			return fmt.Errorf("%w: adds[%d] publishes %x", ErrAddDuplicateEncryptionKey, i, key)
		}
		seen[key] = true
	}
	return nil
}

// ValSem104InitNotEqualEncryptionKey: an Add's init key differs from its leaf's encryption key.
//
// Equal keys would make the Welcome ciphertext and the update path ciphertext openable by one
// private key, which collapses the separation between joining the group and being in it.
//
// The comparison is crypto/subtle.ConstantTimeCompare and not bytes.Equal, for guardrail 8's
// reason as this package states it everywhere else: nothing this package ships compares data with
// a variable-time call, in any file, and the class that holds that is derived off the imports
// rather than off a list of banned names.
func ValSem104InitNotEqualEncryptionKey(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	for i := range in.List.Adds {
		kp := &in.List.Adds[i].Proposal.Add.KeyPackage
		if subtle.ConstantTimeCompare(kp.InitKey, kp.LeafNode.EncryptionKey) == 1 {
			return fmt.Errorf("%w: adds[%d]", ErrInitEqualsEncryptionKey, i)
		}
	}
	return nil
}

// ValSem105SuiteAndVersionMatch: an Add's KeyPackage names this group's ciphersuite and protocol
// version, and is otherwise valid per RFC 9420 section 10.1.
//
// The section 10.1 half answers key_package.go's own refusals rather than a value of this file's:
// "this key package is not well formed" is a different fact from "this key package is for another
// group", a caller repairs the two at opposite ends, and KeyPackage.Validate is the single
// declaration site for the first of them.
func ValSem105SuiteAndVersionMatch(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	for i := range in.List.Adds {
		kp := &in.List.Adds[i].Proposal.Add.KeyPackage
		if kp.CipherSuite != in.Context.CipherSuite || kp.Version != in.Context.Version {
			return fmt.Errorf("%w: adds[%d] is version %#04x suite %#04x, the group is %#04x %#04x",
				ErrSuiteMismatch, i, uint16(kp.Version), uint16(kp.CipherSuite),
				uint16(in.Context.Version), uint16(in.Context.CipherSuite))
		}
		if err := kp.Validate(in.Crypto, in.Context.CipherSuite, in.Now); err != nil {
			return fmt.Errorf("%w: at adds[%d]", err, i)
		}
	}
	return nil
}

// ValSem106RequiredCapabilitiesSatisfied: an added member supports every required capability,
// including any a GroupContextExtensions proposal in this same commit adds.
func ValSem106RequiredCapabilitiesSatisfied(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	required, err := requiredCapabilitiesOf(in.effectiveExtensions())
	if err != nil || required == nil {
		return err
	}
	for i := range in.List.Adds {
		caps := &in.List.Adds[i].Proposal.Add.KeyPackage.LeafNode.Capabilities
		if err := caps.Supports(required); err != nil {
			return fmt.Errorf("%w: adds[%d]: %v", ErrAddMissingRequiredCapability, i, err)
		}
	}
	return nil
}

// ValSem107UniqueRemove: a leaf is removed at most once.
func ValSem107UniqueRemove(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	seen := map[LeafIndex]bool{}
	for i := range in.List.Removes {
		leafIndex := in.List.Removes[i].Proposal.Remove.Removed
		if seen[leafIndex] {
			return fmt.Errorf("%w: leaf %d, at removes[%d]", ErrDuplicateRemove, leafIndex, i)
		}
		seen[leafIndex] = true
	}
	return nil
}

// ValSem108RemoveExists: a removed leaf is a non-blank leaf of the PRE-commit tree.
//
// Pre-commit and not post: the tree this reads is the one every rule of this file reads, and a
// list removing a leaf another entry of the same list also removes is ValSem107's rule rather
// than this one.
func ValSem108RemoveExists(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	for i := range in.List.Removes {
		leafIndex := in.List.Removes[i].Proposal.Remove.Removed
		if in.Tree.Leaf(leafIndex) == nil {
			return fmt.Errorf("%w: leaf %d, at removes[%d]", ErrRemoveNonMember, leafIndex, i)
		}
	}
	return nil
}

// ValSem109UpdateRequiredCapabilities: an updated leaf still supports the group's required
// capabilities.
//
// RFC 9420 as published imposes the group-extension compatibility check on the client ADDING a
// member and on nobody updating one; erratum 8745 is the report that the omission contradicts
// section 13.4's own conclusion about all members of the group. This package acts on the erratum
// -- see ERRATA.md and (*LeafNode).Validate -- and this rule is that decision at the list level.
func ValSem109UpdateRequiredCapabilities(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	required, err := requiredCapabilitiesOf(in.effectiveExtensions())
	if err != nil || required == nil {
		return err
	}
	for i := range in.List.Updates {
		caps := &in.List.Updates[i].Proposal.Update.LeafNode.Capabilities
		if err := caps.Supports(required); err != nil {
			return fmt.Errorf("%w: updates[%d]: %v", ErrUpdateMissingRequiredCapability, i, err)
		}
	}
	return nil
}

// ValSem110UpdateUniqueEncryptionKey: an Update's encryption key is unique among the proposals and
// among current members, so an update cannot reinstate a key another leaf already holds.
//
// The members' half excludes the leaves this list UPDATES as well as the ones it removes, because
// a leaf's own outgoing key is exactly the key it is replacing: without that exclusion a member
// republishing anything at all would be refused for colliding with itself.
func ValSem110UpdateUniqueEncryptionKey(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	seen := map[string]bool{}
	removed := removedLeaves(in.List)
	updated := map[LeafIndex]bool{}
	for i := range in.List.Updates {
		updated[in.List.Updates[i].Sender] = true
	}
	for _, leafIndex := range in.Tree.NonBlankLeaves() {
		if removed[leafIndex] || updated[leafIndex] {
			continue
		}
		leaf := in.Tree.Leaf(leafIndex)
		if leaf == nil {
			continue
		}
		seen[string(leaf.EncryptionKey)] = true
	}
	for i := range in.List.Adds {
		seen[string(in.List.Adds[i].Proposal.Add.KeyPackage.LeafNode.EncryptionKey)] = true
	}
	for i := range in.List.Updates {
		key := string(in.List.Updates[i].Proposal.Update.LeafNode.EncryptionKey)
		if seen[key] {
			return fmt.Errorf("%w: updates[%d] publishes %x", ErrUpdateDuplicateEncryptionKey, i, key)
		}
		seen[key] = true
	}
	return nil
}

// ValSem111NoCommitterUpdate: the committer must not cover its own Update. Its leaf is reset by
// the UpdatePath instead, so an Update beside it is a second answer to what that leaf holds.
func ValSem111NoCommitterUpdate(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	for i := range in.List.Updates {
		if in.List.Updates[i].Sender == in.Committer {
			return fmt.Errorf("%w: leaf %d, at updates[%d]", ErrSelfUpdateInCommit, in.Committer, i)
		}
	}
	return nil
}

// ValSem112UpdateSenderIsMember: a standalone Update is attributed to a leaf that is occupied in
// the pre-commit tree.
//
// The cache refuses a non-member SENDER TYPE at Store time; this is the other half of the same
// question and the one a list assembled in process has been through neither door of. The two
// answer different values on purpose -- see ErrUpdateSenderNotMember.
func ValSem112UpdateSenderIsMember(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	for i := range in.List.Updates {
		sender := in.List.Updates[i].Sender
		if in.Tree.Leaf(sender) == nil {
			return fmt.Errorf("%w: leaf %d, at updates[%d]", ErrUpdateSenderNotMember, sender, i)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// the two section 12.2 rules that carry no ValSem code
// ---------------------------------------------------------------------------

// validateSingleUpdateOrRemovePerLeaf is RFC 9420 section 12.2's "It contains multiple Update
// and/or Remove proposals that apply to the same leaf".
//
// One SET over both kinds and not a set per kind, because the pair the rule is written for is an
// Update and a Remove landing on one leaf: two removes are ValSem107's rule and are refused
// before this runs, and the mixed pair is refused by nothing else. What a list carrying both
// would do is decide by APPLICATION ORDER what the leaf ends up holding -- section 12.3 applies
// updates before removes, so the leaf is blanked, and an implementation that applied in list
// order would leave the member in the group with a fresh key.
func validateSingleUpdateOrRemovePerLeaf(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	touched := map[LeafIndex]bool{}
	for i := range in.List.Updates {
		sender := in.List.Updates[i].Sender
		if touched[sender] {
			return fmt.Errorf("%w: leaf %d, at updates[%d]", ErrUpdateOrRemoveSameLeaf, sender, i)
		}
		touched[sender] = true
	}
	for i := range in.List.Removes {
		leafIndex := in.List.Removes[i].Proposal.Remove.Removed
		if touched[leafIndex] {
			return fmt.Errorf("%w: leaf %d, at removes[%d]", ErrUpdateOrRemoveSameLeaf, leafIndex, i)
		}
		touched[leafIndex] = true
	}
	return nil
}

// validateCommitterIsNotRemoved is RFC 9420 section 12.2's "It contains a Remove proposal that
// removes the committer".
//
// The plan's thirteen do not carry it, and it is not implied by any of them: ValSem108 accepts
// the committer's leaf because the committer is a member, and ValSem107 accepts a single remove.
// A commit carrying one would advance the epoch, seal a welcome and a path from a leaf the same
// commit blanks, and leave every receiver applying a tree whose only writer is no longer in it.
func validateCommitterIsNotRemoved(in *ProposalValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	for i := range in.List.Removes {
		if in.List.Removes[i].Proposal.Remove.Removed == in.Committer {
			return fmt.Errorf("%w: leaf %d, at removes[%d]", ErrRemoveCommitter, in.Committer, i)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// the two readers the rules above share
// ---------------------------------------------------------------------------

// removedLeaves is the set of leaves this list removes.
func removedLeaves(list *ProposalList) map[LeafIndex]bool {
	out := map[LeafIndex]bool{}
	for i := range list.Removes {
		out[list.Removes[i].Proposal.Remove.Removed] = true
	}
	return out
}

// requiredCapabilitiesOf finds and decodes the required_capabilities extension. It answers a nil
// structure and a nil error when the group requires nothing.
//
// FindExtension and syntax.Unmarshal are the only two calls: there is one extension lookup and
// one decoder in this package, and this file adds neither.
//
// BOTH FAILURES ARE REFUSALS rather than "no requirement", which is the one place this differs
// from the plan's sketch and the difference is a security one. A vector carrying the extension
// twice, or carrying a body that does not decode, read as "the group requires nothing" would
// admit a member who supports none of it -- so a malformed extension would be strictly better for
// an attacker than a well formed one. ErrMalformedExtension is the value both answer because they
// are one rule: the extension the group's own context carries is not readable.
func requiredCapabilitiesOf(exts []Extension) (*RequiredCapabilities, error) {
	data, found, err := FindExtension(exts, ExtensionTypeRequiredCapabilities)
	if err != nil {
		return nil, fmt.Errorf("%w: required_capabilities: %v", ErrMalformedExtension, err)
	}
	if !found {
		return nil, nil
	}
	var required RequiredCapabilities
	if err := syntax.Unmarshal(data, &required); err != nil {
		return nil, fmt.Errorf("%w: required_capabilities: %v", ErrMalformedExtension, err)
	}
	return &required, nil
}
