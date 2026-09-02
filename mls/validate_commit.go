// RFC 9420 section 12.4.2 commit validation: one named function per ValSem code of the 200 series,
// ValSem300, and the two errata acceptance criterion 3 names.
//
// WHAT THIS FILE JUDGES AND WHAT IT DOES NOT. Every rule here is a function of a commit, the two
// trees it sits between, and the group context -- no private key material and no signature. That
// is a deliberate line and it is the same one ValSem205 is drawn on the far side of: the
// confirmation tag cannot be computed until the new key schedule exists, so it is declared here
// and run by the caller that has one. The two cryptographic doors of section 12.4.2 -- the
// section 7.3 leaf validation of the update path's leaf (treekem.go's ValidateUpdatePathLeafNode)
// and the path decryption (treekem.go's DecryptUpdatePath) -- are the same shape and are p7 task
// 18's, which is the layer that holds the receiver's own key material. Nothing here restates
// either of them, because a rule enforced at two doors with two bodies is a rule two doors
// enforce differently.
//
// ONE VALUE PER RULE, which is errors_lifecycle.go's rule and errors_proposal_validation.go's,
// and it is the reason several rules below answer sentinels this file does not declare. ValSem200
// is section 12.2's "it contains a Remove proposal that removes the committer" asked at the commit
// door, so it DELEGATES to validate_proposals.go's body and answers ErrRemoveCommitter; a second
// comparison here answering a second value would be one rule a caller could not ask about with one
// errors.Is. The same holds for ValSem208 and errMultipleGroupContextExtensions, for ValSem207 and
// CheckUpdatePathKeyUniqueness, and for CheckErrata8815 and errProposalNotCached. What this file
// DOES declare is a value for each rule that had none.
//
// WHERE THIS FILE DEPARTS FROM THE PLAN IT WAS WRITTEN FROM, because the departures are the part a
// later reader has to be able to check:
//
//   - The plan describes erratum 8745 as "the update path's leaf node must be bound to the new
//     epoch's group context" and writes CheckErrata8745 as a leaf_node_source and parent_hash
//     check. That is not erratum 8745. Erratum 8745 is section 13.4's group-extension
//     compatibility rule extended to "Update proposals and LeafNode objects in the update_path in
//     a Commit" -- ERRATA.md carries it verbatim -- so CheckErrata8745 states THAT, over the leaf
//     an update path publishes, through the same loop (*LeafNode).Validate runs.
//   - The plan describes erratum 8815 as "a commit must not reference a proposal it also carries
//     by value" and writes CheckErrata8815 as a duplicate check. That is not erratum 8815 either.
//     Erratum 8815 adds one clause to section 12.2: "It contains a reference to a proposal that
//     was not previously received by the group member." ERRATA.md carries it. So CheckErrata8815
//     states THAT, and answers proposal_list.go's errProposalNotCached, which is the value
//     (*ProposalCache).Resolve already answers the same question with.
//   - ValSem204's sentinel. treekem.go already carries errPathKeyMismatch for the OTHER rule the
//     ValSem204 label is used for -- a path node whose announced key is not the one its path
//     secret derives, which is a comparison only the decrypt can make. Section 12.4.2 states this
//     rule separately ("verify that the encryption_key value in the LeafNode is different from the
//     committer's current leaf node") and the two faults have different remedies, so they are two
//     values: errPathLeafKeyUnchanged is this one.
//   - ValSem207 does not wrap at all. CheckUpdatePathKeyUniqueness answers three sentinels on
//     purpose -- a collision, a missing tree, a node with no body -- and its own header says a
//     funnel that flattens the chain reports a malformed tree to the group as a commit that
//     duplicated a key. The plan wraps it with %v, which is exactly that flattening; the funnel
//     returns it unchanged rather than adding a fourth name that would make all three read as one.
//   - ValSem209 does not stop at required_capabilities. The plan returns nil when the new
//     extension set carries no required_capabilities extension, which skips section 13.4's own
//     rule -- "an extension in use by the group MUST be supported by all members of the group" --
//     for every group that requires nothing. Both conditions run here.
package mls

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"time"
)

// What commit validation refuses that nothing else in this package already names.
//
// ONE VALUE PER RULE and never one value shared by two, for the reason
// errors_proposal_validation.go's header gives at length: errors.Is cannot tell two rules apart
// when they answer the same value, so a negative test asserting the broad question passes over a
// rule that fired for the wrong reason. TestEveryCommitValidationRefusalIsDistinctFromEveryOther
// holds the class derived from THIS FILE's declarations rather than from a list, and
// TestEachCommitRuleAnswersOnlyItsOwnSentinel builds the input for each rule and requires the
// other rules not to answer.
//
// Unexported, on the shape proposal_list.go, extension.go, framing.go, psk.go, tree.go and
// treekem.go all take: the validation plan owns the exported ValSem catalogue -- ErrMissingPath,
// ErrBadConfirmationTag, ErrUnsupportedGroupExtension and the rest -- and two plans declaring one
// name in one package is a compile error at merge, while the quieter half is a caller matching one
// of two values of one spelling and getting false with nothing to say about it. Every caller of
// these refusals until that plan lands is inside package mls.
// TestNoValidationOwnedNameHasLandedBesideItsStandIn fails on the commit that lands either half of
// such a pair.
var (
	// the argument rules of this file's entry points. Four values and not one, which is the rule
	// ProposalValidationInput.check is held to: a caller that handed over no tree and a caller
	// that handed over no commit have made different mistakes and repair them in different
	// places. Two of the four already exist for exactly these conditions and are not redeclared.
	errNilCommitValidationInput = errors.New("mls: commit validation was handed no input, no commit, no proposal list, no tree or no group context")
	errNilCommit                = errors.New("mls: commit validation has no commit to judge")

	// ValSem201: the path is populated when section 12.4's rule requires one. Its own value and
	// not errPathLength's, because a commit that carries no path at all and a commit whose path
	// is the wrong length are sent by different senders for different reasons -- the first
	// decided it needed no path, the second built one against a different tree.
	errMissingPath = errors.New("mls: the commit carries no update path and its proposal list requires one")

	// ValSem204: section 12.4.2's "verify that the encryption_key value in the LeafNode is
	// different from the committer's current leaf node".
	//
	// It is the exact complement of the one exemption CheckUpdatePathKeyUniqueness makes. That
	// walk lets the committer's outgoing leaf key through AT THE PATH'S LEAF POSITION, because
	// that is the key the path is replacing and an honest commit publishes a fresh one there; a
	// commit that republished the retired key would therefore pass ValSem206 and ValSem207 with
	// nothing to say about it. This is the rule that refuses exactly that pair, so the two
	// together cover every position of the path.
	//
	// A commit that recycles the committer's own leaf key advances the epoch while leaving that
	// leaf decryptable by whoever compromised it, which is the whole of what a path exists to
	// prevent -- and it does so while looking, to every other rule, like an ordinary full commit.
	errPathLeafKeyUnchanged = errors.New("mls: the update path's leaf node republishes the committer's current encryption key")

	// ValSem205: the confirmation tag does not verify. Its own value and not
	// errMissingConfirmationTag's, which framing.go declares for a commit that carries none: a
	// tag that is absent and a tag that is wrong are a malformed message and a forked group, and
	// a caller told only "the confirmation tag" cannot tell which of the two it is holding.
	errBadConfirmationTag = errors.New("mls: the commit's confirmation tag does not verify against this epoch's confirmation key")

	// ValSem204's precondition, and its own value for ValSem112's reason one file over: a commit
	// attributed to a leaf that is blank or outside the tree is a commit whose committer is not a
	// member, and every comparison against "the committer's current leaf" would otherwise be a
	// comparison against a leaf nobody occupies.
	errCommitterNotMember = errors.New("mls: a commit is attributed to a leaf that is blank or outside the tree")

	// ValSem209's profile half, three values for three remedies, which is the split
	// proposal_list.go's checkProposalType already argues for over the proposal registry.
	//
	// errProfileExternalSender is spec A section 3.2's own name for the one v1 refuses by
	// FEATURE: external senders are not implemented, and a peer running a fuller profile can be
	// told exactly that. errProfileGroupExtension is a registered type this profile does not
	// admit IN A GROUP CONTEXT -- urmessage_leaf_keys belongs in a leaf and application_id is not
	// in spec A section 3.1's group-context set -- which is a different sentence with a different
	// remedy. errUnregisteredGroupExtension is a code point this build has never heard of, where
	// there is no narrowing to name at all.
	errProfileExternalSender      = errors.New("mls: the external_senders group context extension is outside the v1 profile")
	errProfileGroupExtension      = errors.New("mls: extension type is registered and outside the v1 profile's group context set")
	errUnregisteredGroupExtension = errors.New("mls: extension type is not in this build's extension type registry")
)

// groupExtensionProfile is the v1 disposition of every REGISTERED extension type as a GROUP
// CONTEXT extension: nil for the four spec A section 3.1 admits, and the sentinel that names why
// for the four it does not.
//
// A map keyed by the registry's own constants rather than a switch listing four accepted names,
// for proposalTypeProfile's reason next door: the accepted set is the complement of a refused set
// and only one of the two can be written down without understating the other. What holds it to the
// registry is TestTheV1ProfileClassifiesEveryRegisteredExtensionTypeAsAGroupContextExtension,
// which reads the ExtensionType constants out of this package's source and compares the two sets
// in BOTH directions: a ninth code point declared in extension.go with no row here fails, and a
// row here for a code point that no longer exists fails too.
//
// application_id and urmessage_leaf_keys are LEAF extensions and are refused here rather than
// omitted, because "not a group context extension" is a decision and a map with a hole in it is
// not one. external_pub answers proposal_list.go's errProfileExternalCommit rather than a value of
// its own: it is the key an external commit joins through, external commits are the feature v1
// does not implement, and a second sentinel for the extension half would be two names for one
// narrowing.
var groupExtensionProfile = map[ExtensionType]error{
	ExtensionTypeApplicationId:           errProfileGroupExtension,
	ExtensionTypeRatchetTree:             nil,
	ExtensionTypeRequiredCapabilities:    nil,
	ExtensionTypeExternalPub:             errProfileExternalCommit,
	ExtensionTypeExternalSenders:         errProfileExternalSender,
	ExtensionTypeUrmessageGroupPolicy:    nil,
	ExtensionTypeUrmessageLeafKeys:       errProfileGroupExtension,
	ExtensionTypeUrmessageOwnerSuccessor: nil,
}

// checkGroupExtension is the one refusal surface for a group context extension type, standing in
// for (*Profile).CheckGroupExtension.
//
// It is a method on proposal_list.go's profile rather than a free function, because the narrowing
// is the PROFILE's and not this file's: p8's Profile carries CheckProposalType and
// CheckGroupExtension beside each other, and a free function here would have to be found and moved
// separately on the day that lands.
func (self *profile) checkGroupExtension(extensionType ExtensionType) error {
	refusal, registered := groupExtensionProfile[extensionType]
	if !registered {
		return fmt.Errorf("%w: extension type %#04x", errUnregisteredGroupExtension, uint16(extensionType))
	}
	if refusal != nil {
		return fmt.Errorf("%w: extension type %#04x", refusal, uint16(extensionType))
	}
	return nil
}

// CommitValidationInput is everything a commit is judged against.
//
// PreTree is the epoch's tree; PostTree is the tree after the proposals were applied and before
// the UpdatePath was merged, which is the state RFC 9420 section 12.4.2's uniqueness and path
// length rules are written against. The two are separate fields rather than one, because ValSem204
// is stated over the committer's CURRENT leaf and ValSem202, ValSem207 and ValSem300 over the tree
// the merge is about to happen in, and a single tree would make one of the two wrong.
//
// Pending is not in the plan's struct and is added rather than left out. CheckErrata8815 is stated
// over the proposals this member has actually received, which is exactly what a ProposalCache
// holds, and a commit validator that could not reach one could not state the erratum at all. A nil
// cache holds nothing, so a commit naming any reference is refused under one -- which is the
// fail-closed direction and is why the aggregate does not condition on it.
type CommitValidationInput struct {
	Crypto          CryptoProvider
	PreTree         *RatchetTree
	PostTree        *RatchetTree
	Context         *GroupContext
	Extensions      []Extension
	Committer       LeafIndex
	Own             LeafIndex
	List            *ProposalList
	Commit          *Commit
	Pending         *ProposalCache
	ConfirmationKey []byte
	ConfirmedHash   []byte
	ConfirmationTag []byte
	Now             time.Time
}

// check is the argument rule every entry point of this file runs first.
//
// A method with a nil-receiver guard rather than a nil comparison in each rule function, which is
// ProposalValidationInput.check's shape and is here for its reason: eleven copies of a guard is
// eleven chances for one of them to be the copy that was not updated. Go calls a method on a nil
// pointer without dereferencing it, so this is reachable from every door.
// TestEveryCommitValidationEntryPointRefusesANilInput drives all of them.
func (self *CommitValidationInput) check() error {
	if self == nil {
		return fmt.Errorf("%w: no validation input", errNilCommitValidationInput)
	}
	if self.Commit == nil {
		return fmt.Errorf("%w: the path and the proposal vector are its", errNilCommit)
	}
	if self.List == nil {
		return fmt.Errorf("%w: section 12.4's path rule is stated over it", errNilProposalList)
	}
	if self.PreTree == nil || self.PostTree == nil {
		return fmt.Errorf("%w: a commit is judged between the tree it arrived in and the tree its proposals build",
			errNilRatchetTree)
	}
	if self.Context == nil {
		return fmt.Errorf("%w: the version, the suite and the group extensions are its", ErrNilGroupContext)
	}
	return nil
}

// effectiveExtensions is the extension list the commit's leaf rules are judged against.
//
// Three sources in one order, and each of the two fallbacks answers a caller that exists, which is
// ProposalValidationInput.effectiveExtensions' argument one file over. Section 12.4.2 applies the
// proposals -- the GroupContextExtensions proposal among them -- BEFORE the path is validated, so
// the extension set a path leaf owes support for is the new one and not the epoch's.
func (self *CommitValidationInput) effectiveExtensions() []Extension {
	if self.Extensions != nil {
		return self.Extensions
	}
	if exts, ok := self.List.Extensions(); ok {
		return exts
	}
	return self.Context.Extensions
}

// effectiveContext is the group context the path's leaf rules run under: the epoch's context with
// the post-proposal extension set in place of its own.
//
// A COPY, so nothing here writes into the caller's group context. A rule that edited the context it
// was handed would leave the caller holding a context whose extensions came from a commit it may
// well have gone on to refuse.
func (self *CommitValidationInput) effectiveContext() *GroupContext {
	replaced := *self.Context
	replaced.Extensions = self.effectiveExtensions()
	return &replaced
}

// The rules ValidateCommit runs over a CommitValidationInput, in the order it runs them.
//
// A slice rather than a straight-line sequence of calls, because what has to be checkable is that
// the aggregate runs EVERY rule and not a subset of them:
// TestValidateCommitRunsEveryRuleThisFileDeclares reads the rule functions out of this file's
// SOURCE -- by signature, so the rules that carry no ValSem code are in the class too -- and
// requires each to appear here or to be written down as deliberately left out, so a twelfth rule
// added below is unrun until somebody puts it in the slice.
//
// ValSem205 is the one deliberate omission and the reason is on ValSem205ConfirmationTag: the
// confirmation key belongs to the epoch this commit OPENS, so it does not exist until the new key
// schedule has been derived, which is one layer above every other rule here.
//
// THE ORDER. The structural rules that make the later ones safe to write run first: ValSem201 and
// ValSem202 decide that there is a path and that it is the right length before any rule indexes
// into it, and the leaf source rule runs before the rules that read the leaf's key, so a commit
// carrying a key_package leaf in its path is reported as that rather than as a key comparison.
var commitValidationChecks = []func(*CommitValidationInput) error{
	ValSem200NoSelfRemove,
	ValSem201PathPresentWhenRequired,
	ValSem202PathLength,
	validateCommitPathLeafSource,
	ValSem203PathDecrypt,
	ValSem204PathKeyMismatch,
	ValSem206PathLeafEncryptionKeyUnique,
	ValSem207PathEncryptionKeysUnique,
	ValSem208SingleGroupContextExtensions,
	ValSem209GroupExtensionsSupported,
	validateCommitErrata,
	validateCommitPostTreeIsExportable,
}

// ValidateCommit runs every rule this file states that can be decided without the new epoch's key
// schedule, in code order.
//
// ValSem205 is run by the caller, because the confirmation key is not derivable until the new key
// schedule exists. The two cryptographic doors of section 12.4.2 -- ValidateUpdatePathLeafNode and
// DecryptUpdatePath -- are p7 task 18's, for the reason this file's header gives.
func ValidateCommit(in *CommitValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	for _, check := range commitValidationChecks {
		if err := check(in); err != nil {
			return err
		}
	}
	return nil
}

// validateCommitErrata runs the two errata over the input's own fields, so the aggregate above
// reaches them without their signatures having to take a CommitValidationInput.
//
// The two errata take a path and a context, and a commit and a cache, because those are what each
// is a rule ABOUT and because p7 task 18 calls them with values it holds rather than with a
// validation input it would have to assemble. This is the adapter, and it is a rule of this file
// in its own right so that the derived gate above sees the errata run.
func validateCommitErrata(in *CommitValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	if err := CheckErrata8745(in.Commit.Path, in.effectiveContext()); err != nil {
		return err
	}
	return CheckErrata8815(in.Commit, in.Pending)
}

// validateCommitPostTreeIsExportable is the same adapter for ValSem300, which is stated over a
// tree rather than over a commit because that is what it is a rule about: task 16's welcome path
// asks it of a tree that arrived in a GroupInfo and holds no commit at all.
func validateCommitPostTreeIsExportable(in *CommitValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	return ValSem300NoTrailingBlankNodes(in.PostTree)
}

// ValSem200NoSelfRemove: a commit must not cover a Remove of the committer.
//
// RFC 9420 section 12.2's "it contains a Remove proposal that removes the committer", which
// validate_proposals.go already states over a proposal list. This DELEGATES to that body rather
// than repeating the loop, and answers ErrRemoveCommitter rather than a value of its own. Two
// bodies comparing the same two numbers is how one of them comes to be edited and the other not,
// and two values for one rule is a caller that cannot ask the question with one errors.Is.
//
// The precondition is the one validate_proposals.go's header states: the structural rules of
// section 12.2 run before the rules that read a proposal's arm. A commit whose list has not been
// through them is a list that may hold a Remove with no Remove arm, and this reads that arm.
func ValSem200NoSelfRemove(in *CommitValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	return validateCommitterIsNotRemoved(in.proposalValidationInput())
}

// proposalValidationInput is the section 12.2 input this file's two delegating rules hand over.
//
// One builder and not two literals, so the two cannot come to disagree about which tree section
// 12.2 is stated over. It is the PRE-commit tree, which is section 12.2's own subject -- every
// membership rule there is about the group the proposals arrived in.
func (self *CommitValidationInput) proposalValidationInput() *ProposalValidationInput {
	return &ProposalValidationInput{
		Crypto:     self.Crypto,
		Tree:       self.PreTree,
		Context:    self.Context,
		Extensions: self.Extensions,
		Committer:  self.Committer,
		List:       self.List,
		Now:        self.Now,
	}
}

// ValSem201PathPresentWhenRequired: the path is populated when the proposal list is empty or
// contains a path-required type.
func ValSem201PathPresentWhenRequired(in *CommitValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	if CommitPathRequired(in.List) && in.Commit.Path == nil {
		return fmt.Errorf("%w: %d proposals, none of which lets the path be omitted",
			errMissingPath, in.List.Len())
	}
	return nil
}

// ValSem202PathLength: the path has exactly one node per entry in the committer's filtered direct
// path in the post-proposal tree.
//
// The POST-proposal tree, because the proposals are applied before the path is validated and a
// remove blanks nodes the filter then steps over. Against the pre-proposal tree an honest commit
// would be refused whenever its list removes anybody.
func ValSem202PathLength(in *CommitValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	if in.Commit.Path == nil {
		return nil
	}
	filtered, err := in.PostTree.FilteredDirectPath(in.Committer)
	if err != nil {
		return fmt.Errorf("%w: the committer's filtered direct path could not be read: %w", errPathLength, err)
	}
	if len(in.Commit.Path.Nodes) != len(filtered) {
		return fmt.Errorf("%w: path has %d nodes, the filtered direct path has %d",
			errPathLength, len(in.Commit.Path.Nodes), len(filtered))
	}
	return nil
}

// validateCommitPathLeafSource: section 12.4.2's "the leaf_node_source field MUST be set to
// commit", stated structurally.
//
// The RFC states it as a bullet of its own beside "validate the LeafNode as specified in Section
// 7.3", and this is the structural one. The section 7.3 door is ValidateUpdatePathLeafNode, which
// needs a provider and verifies a signature, and it is p7 task 18's call. The two answer ONE
// sentinel -- ErrLeafNodeSourceMismatch -- because they are one rule at two doors; what a second
// value would buy is a caller that cannot tell which of them fired.
//
// Without it a commit's path can carry a key_package sourced leaf, whose signature covers a
// lifetime and no group id and whose encoding carries no parent_hash at all -- so every later rule
// that reads the leaf's parent_hash is reading a field the leaf's own signature does not cover.
func validateCommitPathLeafSource(in *CommitValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	if in.Commit.Path == nil {
		return nil
	}
	if in.Commit.Path.LeafNode.LeafNodeSource != LeafNodeSourceCommit {
		return fmt.Errorf("%w: the update path's leaf_node_source is %d and section 12.4.2 takes commit",
			ErrLeafNodeSourceMismatch, uint8(in.Commit.Path.LeafNode.LeafNodeSource))
	}
	return nil
}

// ValSem203PathDecrypt: the path carries a secret this receiver can open.
//
// CommitValidationInput deliberately holds no private key material -- it is the input every rule
// here shares, and putting a private key in it would put one in every negative test's fixture. So
// this is the STRUCTURAL half: every path node addresses a non-empty ciphertext vector, and this
// receiver's own filtered direct path meets the committer's somewhere, so a ciphertext exists that
// is addressed to it. The cryptographic half runs at the DecryptUpdatePath call site in commit
// processing and answers the SAME sentinel, so errors.Is(err, errPathDecrypt) holds for both and
// ValSem203 has one code.
//
// EVERY node and not the first, which is the p4 ValSem401 shape this package has shipped four
// times: a path whose only empty ciphertext vector sits at node 1 addresses nobody at that rung,
// and every member reached through it derives nothing.
func ValSem203PathDecrypt(in *CommitValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	if in.Commit.Path == nil {
		return nil
	}
	for i := range in.Commit.Path.Nodes {
		if len(in.Commit.Path.Nodes[i].EncryptedPathSecret) == 0 {
			return fmt.Errorf("%w: update path node %d encrypts to nobody", errPathDecrypt, i)
		}
	}
	// the committer seals nothing to itself and needs nothing: it holds every secret it derived.
	if in.Own == in.Committer {
		return nil
	}
	ownPath, err := in.PostTree.FilteredDirectPath(in.Own)
	if err != nil {
		return fmt.Errorf("%w: this member's filtered direct path could not be read: %w", errPathDecrypt, err)
	}
	committerPath, err := in.PostTree.FilteredDirectPath(in.Committer)
	if err != nil {
		return fmt.Errorf("%w: the committer's filtered direct path could not be read: %w", errPathDecrypt, err)
	}
	for _, x := range committerPath {
		for _, y := range ownPath {
			if x == y {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: leaf %d shares no node with the committer's filtered direct path",
		errPathDecrypt, in.Own)
}

// ValSem204PathKeyMismatch: section 12.4.2's "verify that the encryption_key value in the LeafNode
// is different from the committer's current leaf node".
//
// See errPathLeafKeyUnchanged: this is the exact complement of the one exemption
// CheckUpdatePathKeyUniqueness makes, so the two together cover every position of the path.
//
// The comparison is subtle.ConstantTimeCompare and not bytes.Equal, which is this package's rule
// over every comparison of data it ships and is derived rather than listed;
// TestNothingThisPackageShipsComparesDataOutsideConstantTime is what holds it.
func ValSem204PathKeyMismatch(in *CommitValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	if in.Commit.Path == nil {
		return nil
	}
	current := in.PreTree.Leaf(in.Committer)
	if current == nil {
		return fmt.Errorf("%w: leaf %d", errCommitterNotMember, in.Committer)
	}
	if subtle.ConstantTimeCompare(current.EncryptionKey, in.Commit.Path.LeafNode.EncryptionKey) == 1 {
		return fmt.Errorf("%w: leaf %d", errPathLeafKeyUnchanged, in.Committer)
	}
	return nil
}

// ValSem205ConfirmationTag: the confirmation tag equals MAC(confirmation_key,
// confirmed_transcript_hash) for the NEW epoch.
//
// Not in commitValidationChecks, and the reason is not an omission: the confirmation key is
// derived from the epoch this commit OPENS, so it does not exist until the key schedule has been
// advanced -- which is a step section 12.4.2 puts after every rule above. The caller that has one
// runs this.
//
// The comparison goes through CryptoProvider.MacVerify and reaches subtle.ConstantTimeCompare
// there, which is guardrail 8 and is the only route this package allows to a tag comparison;
// TestEveryTagVerifierComparesThroughMacVerifyAndNothingElse holds it.
func ValSem205ConfirmationTag(in *CommitValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	if in.Crypto == nil {
		return fmt.Errorf("%w: the tag is verified through it", ErrNilCryptoProvider)
	}
	if len(in.ConfirmationTag) == 0 {
		return errMissingConfirmationTag
	}
	if !in.Crypto.MacVerify(in.ConfirmationKey, in.ConfirmedHash, in.ConfirmationTag) {
		return fmt.Errorf("%w: the group has forked or the commit was tampered with", errBadConfirmationTag)
	}
	return nil
}

// ValSem206PathLeafEncryptionKeyUnique: the path leaf's encryption key is not one this commit's own
// proposals publish.
//
// THE AXIS CheckUpdatePathKeyUniqueness CANNOT SEE, and that is the whole reason this is a rule of
// its own rather than a second call of that walk. Spec A states these two rows as "unique among
// proposals and members"; the walk next door sees one tree and no proposal list, and its own header
// says so -- it is the CALLER that puts the proposals in range by handing over a post-proposal
// tree. A caller that has not applied the proposals yet, which is every sender assembling a commit,
// hands over a tree the added and updated leaves are not in, and over those inputs the proposals
// axis is enforced by nothing at all.
//
// The added leaf's INIT key is judged too. An init key and a leaf encryption key are both HPKE
// public keys of one suite, ValSem104 already refuses an Add whose init key is its own leaf's
// encryption key, and a path leaf that republished a joiner's init key would open the welcome
// secrets sealed to that joiner.
//
// EVERY proposal and not the first: the loop is what makes this a rule about the list rather than
// about its head, and a list carrying one add is the fixture shape that hides the difference.
func ValSem206PathLeafEncryptionKeyUnique(in *CommitValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	if in.Commit.Path == nil {
		return nil
	}
	key := in.Commit.Path.LeafNode.EncryptionKey
	for i := range in.List.Adds {
		add := in.List.Adds[i].Proposal.Add
		if add == nil {
			continue
		}
		if subtle.ConstantTimeCompare(add.KeyPackage.LeafNode.EncryptionKey, key) == 1 {
			return fmt.Errorf("%w: the update path's leaf key is published by the add at index %d",
				errDuplicateEncryptionKey, i)
		}
		if subtle.ConstantTimeCompare(add.KeyPackage.InitKey, key) == 1 {
			return fmt.Errorf("%w: the update path's leaf key is the init key of the add at index %d",
				errDuplicateEncryptionKey, i)
		}
	}
	for i := range in.List.Updates {
		update := in.List.Updates[i].Proposal.Update
		if update == nil {
			continue
		}
		if subtle.ConstantTimeCompare(update.LeafNode.EncryptionKey, key) == 1 {
			return fmt.Errorf("%w: the update path's leaf key is published by the update at index %d",
				errDuplicateEncryptionKey, i)
		}
	}
	return nil
}

// ValSem207PathEncryptionKeysUnique: section 12.4.2's "verify that none of the public keys in the
// UpdatePath appear in any node of the new ratchet tree".
//
// The walk is CheckUpdatePathKeyUniqueness in tree_sync.go, because it reads the private node
// array and because it is the body that knows which single position the committer's outgoing key
// is exempt at. This is the ValSem-named funnel onto it.
//
// The error is returned UNCHANGED rather than wrapped in a name of this file's. That function
// answers three sentinels on purpose -- errDuplicateEncryptionKey for a collision, ErrTreeMalformed
// for a missing tree, ErrNodeTypeMismatch for an occupied node with no body -- and its own header
// says a funnel that flattens them reports a malformed tree to the group as a commit that
// duplicated a key, which names the wrong party for a fault that is not the committer's.
func ValSem207PathEncryptionKeysUnique(in *CommitValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	if in.Commit.Path == nil {
		return nil
	}
	return CheckUpdatePathKeyUniqueness(in.PostTree, in.Commit.Path)
}

// ValSem208SingleGroupContextExtensions: at most one GroupContextExtensions proposal per commit.
//
// RFC 9420 section 12.2's "it contains multiple GroupContextExtensions proposals", which
// validate_proposals.go already states. It DELEGATES for ValSem200's reason and answers
// errMultipleGroupContextExtensions rather than a value of its own.
func ValSem208SingleGroupContextExtensions(in *CommitValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	return validateOneGroupContextExtensions(in.proposalValidationInput())
}

// ValSem209GroupExtensionsSupported: a GroupContextExtensions proposal may only install extensions
// this profile admits and every member supports.
//
// THREE CONDITIONS, and the plan this was written from states one of them.
//
//  1. The v1 profile admits the extension type at all. Spec A section 3.1 lists ratchet_tree,
//     required_capabilities, urmessage_group_policy and urmessage_owner_successor;
//     checkGroupExtension is the derived gate and names which of the three refusals applies.
//  2. RFC 9420 section 13.4, as corrected by erratum 8745: "an extension in use by the group MUST
//     be supported by all members of the group". This is the condition the plan omits, by
//     returning nil whenever the new set carries no required_capabilities extension -- which is
//     every group that requires nothing, and the check it skips is the one section 13.4 states
//     unconditionally. A GCE installing urmessage_group_policy into a group holding one member
//     who does not list it is exactly the state section 13.4 says cannot happen.
//  3. Section 7.3's required_capabilities rule over the NEW required_capabilities: every remaining
//     member lists the extensions, proposals and credential types it names.
//
// Conditions 2 and 3 are stated over the members the commit LEAVES in the group. A member this
// commit removes is not a member of the epoch the extensions take effect in, and holding the
// commit to its capabilities would refuse the very commit that evicts the member who cannot
// support the new extension.
//
// EVERY member and every extension in all three, rather than the first of either. A group context
// carries several extensions and the ones it carries first are exactly the ones section 7.2 exempts
// from being listed, so a loop that answered element zero steps over the exempt entry and never
// reaches the one behind it -- which is the consequence ERRATA.md records for this same rule inside
// (*LeafNode).Validate.
func ValSem209GroupExtensionsSupported(in *CommitValidationInput) error {
	if err := in.check(); err != nil {
		return err
	}
	exts, carried := in.List.Extensions()
	if !carried {
		// no GroupContextExtensions proposal: this commit installs nothing, and the group's
		// existing extensions were judged by the commit that installed them.
		return nil
	}
	active := defaultProfile()
	for i := range exts {
		if err := active.checkGroupExtension(exts[i].ExtensionType); err != nil {
			return fmt.Errorf("%w: at group_context_extensions entry %d", err, i)
		}
	}
	required, err := requiredCapabilitiesOf(exts)
	if err != nil {
		return err
	}
	removed := removedLeaves(in.List)
	for _, leafIndex := range in.PostTree.NonBlankLeaves() {
		if removed[leafIndex] {
			continue
		}
		leaf := in.PostTree.Leaf(leafIndex)
		if leaf == nil {
			continue
		}
		if err := leaf.checkGroupContextExtensions(exts); err != nil {
			return fmt.Errorf("%w: at leaf %d", err, leafIndex)
		}
		if err := leaf.Capabilities.Supports(required); err != nil {
			return fmt.Errorf("%w: at leaf %d", err, leafIndex)
		}
	}
	return nil
}

// ValSem300NoTrailingBlankNodes: the ratchet tree carries no trailing blank nodes, so two
// implementations cannot produce two encodings of one tree.
//
// RFC 9420 section 12.4.3.3 states it of an EXPORTED ratchet tree, and it is asked of the
// post-commit tree here because that is the tree a GroupInfo published from this commit carries.
// (*RatchetTree).RemoveLeaf truncates, so a tree this package built never has them; a tree that
// does is one decoded from the wire, and this is the second place that says so.
func ValSem300NoTrailingBlankNodes(tree *RatchetTree) error {
	if tree == nil {
		return fmt.Errorf("%w: there is no tree to check for trailing blank nodes", ErrTreeMalformed)
	}
	if tree.HasTrailingBlankNodes() {
		return errTrailingBlankNodes
	}
	return nil
}

// CheckErrata8745 is RFC 9420 erratum 8745 over the leaf an UpdatePath publishes.
//
// THE ERRATUM IS NOT WHAT THE PLAN SAYS IT IS, and ERRATA.md carries it verbatim. It adds one
// bullet to section 13.4: "A client updating a leaf node in the group MUST verify that the new
// LeafNode is compatible with the group's extensions. The capabilities field MUST indicate support
// for each extension in the GroupContext. This applies both to Update proposals and LeafNode
// objects in the update_path in a Commit." The published text imposes that check on the client
// ADDING a member and on nobody updating one, while asserting a conclusion about all members of
// the group -- so without the correction a member can commit an update_path whose leaf drops
// support for an extension the group is using.
//
// It runs the SAME loop (*LeafNode).Validate runs and answers the same sentinel, because it is the
// same rule: two bodies applying one rule is how the two come to disagree, and a second sentinel
// would be a caller that cannot ask the question once. What makes this a door of its own is that
// it is a pure function of a leaf and a context -- no provider, no signature -- so the structural
// commit validator states the erratum before the cryptographic section 7.3 door has run.
//
// A nil path is nil rather than a refusal: an absent path publishes no leaf, so this erratum has
// nothing to say about it, and whether the path was allowed to be absent is ValSem201's rule with
// ValSem201's sentinel.
func CheckErrata8745(path *UpdatePath, context *GroupContext) error {
	if path == nil {
		return nil
	}
	if context == nil {
		return fmt.Errorf("%w: the extensions the update path's leaf owes support for are its",
			ErrNilGroupContext)
	}
	if err := path.LeafNode.checkGroupContextExtensions(context.Extensions); err != nil {
		return fmt.Errorf("%w (erratum 8745)", err)
	}
	return nil
}

// CheckErrata8815 is RFC 9420 erratum 8815 over a commit's ProposalOrRef vector.
//
// THE ERRATUM IS NOT WHAT THE PLAN SAYS IT IS, and ERRATA.md carries it. It adds one clause to
// section 12.2's list of what makes a proposal list invalid: "It contains a reference to a proposal
// that was not previously received by the group member." Section 12.4 lets a commit name proposals
// by reference and section 12.2 states no rule about those references at all, which is the gap the
// erratum names.
//
// It answers proposal_list.go's errProposalNotCached, which is the value (*ProposalCache).Resolve
// already answers this exact question with. One rule, one value, two doors: Resolve asks it while
// turning a vector into a list, and this asks it of a vector nothing has resolved -- a commit this
// client is about to send, or one whose list arrived already bucketed.
//
// A NIL CACHE REFUSES EVERY REFERENCE, and that is the fail-closed direction rather than an
// oversight. The rule is "this member has received the proposal"; a validator handed no record of
// what this member received has not checked that, and answering nil would be a rule that reports
// clean by having nothing to read. A commit carrying only by-value proposals names no reference and
// passes under a nil cache, which is the correct answer for it.
//
// By-value entries are not judged here. A proposal carried inline is one the commit itself
// delivers, so "previously received" is not a question about it, and its own validity is section
// 12.1's rule and ValSem113's gate.
//
// EVERY entry and not the first: a commit whose only uncached reference is its second is exactly
// the shape a rule written over entry zero admits.
func CheckErrata8815(commit *Commit, pending *ProposalCache) error {
	if commit == nil {
		return nil
	}
	for i := range commit.Proposals {
		entry := commit.Proposals[i]
		if entry.Type != ProposalOrRefTypeReference {
			continue
		}
		if !pending.holds(entry.Reference) {
			return fmt.Errorf("%w: entry %d names %x (erratum 8815)",
				errProposalNotCached, i, entry.Reference)
		}
	}
	return nil
}
