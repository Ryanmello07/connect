// RFC 9420 section 12.4's commit rules that are decisions rather than encodings.
//
// The Commit wire struct and its codec are commit_wire.go's, with the rest of the framing types,
// and nothing about the bytes is decided here. What lives here is the rule that says whether a
// commit must carry an UpdatePath at all -- which is a lifecycle decision, made identically by the
// member BUILDING a commit and by every member receiving one, and made from the proposal list
// alone. This file grows as the rest of the commit lifecycle lands; today it holds one rule.
package mls

// CommitPathRequired is RFC 9420 section 12.4's pseudocode, verbatim:
//
//	pathRequiredTypes = [update, remove, external_init, group_context_extensions]
//	pathRequired = false
//	for proposal in commit.proposals:
//	    pathRequired = pathRequired || (proposal.msg_type in pathRequiredTypes)
//	if len(commit.proposals) == 0 || pathRequired:
//	    assert(commit.path != null)
//
// It DELEGATES to (*ProposalList).PathRequired rather than restating the loop, and that is the
// whole reason this function is three lines instead of ten. The sender asks this question when it
// decides whether to build a path and the receiver asks it as ValSem201; a second transcription of
// the same rule is two answers that agree until somebody edits one of them, and the input that
// separates them is a commit this build emits and refuses to receive. proposal_list.go states the
// type set once, over the whole RFC registry rather than over the four types this profile
// implements, and its own header says why.
//
// A NIL LIST IS "PATH REQUIRED", and it is answered here rather than left to a nil dereference
// inside the method. The empty half of the RFC's rule is what makes that the safe answer: a commit
// naming no proposals must carry a path, so a caller that handed over no list at all is asking
// about a commit that names no proposals. The other direction would be a validator that let a
// pathless commit through because its caller forgot an argument, which is the one failure mode
// section 12.4's empty clause exists to prevent -- an epoch that advances over key material every
// member of the previous epoch still holds.
func CommitPathRequired(list *ProposalList) bool {
	if list == nil {
		return true
	}
	return list.PathRequired()
}

// ---------------------------------------------------------------------------
// RFC 9420 section 12.4.1: what a commit generation is allowed to choose, what
// it answers, and the epoch it stages
// ---------------------------------------------------------------------------

// CommitOptions are the committer's discretionary choices. Nothing an exported field here can do
// makes an invalid commit valid: every option below is read BEFORE (*Group).Commit's own doors run,
// and the commit it produces goes through ValidateCommit whatever they say.
type CommitOptions struct {
	// Force populates the update path even when the proposal list does not require one, which
	// buys post compromise security for the committer at the cost of one HPKE seal per node of
	// its filtered direct path. RFC 9420 section 12.4 permits an add-only commit to omit it.
	Force bool

	// ExtraProposals are by-value proposals appended after the byValue argument, attributed to
	// the committer like every other by-value proposal. It is a second by-value channel rather
	// than a different kind of proposal: connect/message assembles the list a user asked for and
	// this profile appends the ones the POLICY requires beside it.
	ExtraProposals []Proposal

	// The three seams below make a commit this package would never send, and they are UNEXPORTED
	// so that no package but this one can set them: p8's ValSem tests need a commit whose
	// confirmation tag is missing, is taken over the wrong transcript, or whose list this
	// package's own doors refuse, and every exported entry point here computes all three itself.
	//
	// THEY ARE FIELDS OF CommitOptions AND NOT OF Commit, which is the plan's own decision and is
	// load bearing: Commit is a wire structure, and a flag on it would change what
	// syntax.Marshal(commit) emits and therefore what every confirmed transcript hash covers.
	//
	// WHAT THE COMPILER HOLDS HERE IS LESS THAN framing_group_seams_test.go GETS, and that is said
	// out loud rather than left to be discovered. Those two seams are declarations of the TEST
	// BINARY, so a production caller does not build at all; these are fields of a production type,
	// so the compiler stops only the packages that are not this one. What stops this one is review.
	skipValidation                         bool
	dropConfirmationTag                    bool
	confirmationTagOverPreCommitTranscript bool
}

// CommitResult is what a committer sends: the commit itself, the Welcome for the members it adds,
// and the post-commit tree those members are handed out of band.
//
// Three octet strings and no structures, because these three cross a process boundary --
// connect/message publishes them and holds no mls type. Every one of them is freshly encoded
// storage the caller owns.
type CommitResult struct {
	// Commit is an MLSMessage(PrivateMessage) carrying the Commit, sealed under the epoch the
	// commit CLOSES, because that is the epoch every recipient is still in.
	Commit []byte
	// Welcome is an MLSMessage(Welcome), nil when the commit adds nobody.
	Welcome []byte
	// RatchetTree is the post-commit public tree, for out-of-band Welcome delivery.
	RatchetTree []byte
}

// StagedCommit is a commit that has been validated and whose new epoch has been derived, but which
// has not replaced the group's live state.
//
// A commit is staged on BOTH sides and that is why this type is not a detail of the send path. The
// committer stages its own and merges when the delivery service accepts it, because the service
// accepts at most one commit per (group, epoch) and a committer that merged optimistically would
// fork itself off the group (MASTER section 9.3). A receiver stages an inbound one so that a policy
// decision -- and, for a commit that removes this client, a decision about what to keep -- can
// happen before the epoch advances.
//
// EVERY FIELD IS UNEXPORTED AND THE ACCESSORS ANSWER COPIES, for the reason (*Group)'s own
// accessors do: this value holds the tree, the schedule and the transcript a merge is about to
// install, and a caller writing through any of them would be editing the epoch this client is about
// to enter with nothing downstream able to report it.
type StagedCommit struct {
	committer LeafIndex
	epoch     uint64
	context   *GroupContext
	// the same context with its authority established, which is what an epoch boundary owes the
	// proposal cache. It is built HERE rather than at the merge so that a commit whose own
	// GroupInfo this client cannot sign or verify is refused before anything is sealed --
	// (*ProposalCache).Rebind takes nothing else, and a merge that could not produce one would
	// leave the group in the new epoch with a cache bound to the epoch that closed.
	verified   *VerifiedGroupContext
	tree       *RatchetTree
	schedule   *KeySchedule
	secretTree *SecretTree
	ownPriv    *TreeKEMPrivate
	transcript *TranscriptHashes
	list       *ProposalList
	// the commit this stages, as the structure the sender signed. Task 18 stages an inbound one
	// the same way, and the send path keeps it for the reason the receive path will: what a
	// merge, a re-validation or a report has to be able to name is the commit itself and not a
	// summary somebody took of it.
	commit      *Commit
	added       []LeafIndex
	removed     []LeafIndex
	updated     []LeafIndex
	selfRemoved bool
	hasPath     bool
	confirmTag  []byte
	plan        *UpdatePathPlan

	// which constructor the new epoch's schedule came from, which is what task 19's LoadGroup
	// needs in order to know what to rebuild it from. THE SECRET ITSELF IS NOT HERE, for the
	// reason (*Group).restoreKind states one file over: the schedule already retains it, its
	// erase is held by the type that DECLARES that storage, and a second copy parked here would
	// be the same secret held by nothing but a hand written Close.
	restoreKind restoreKind
}

// Epoch is the epoch this commit opens.
func (self *StagedCommit) Epoch() uint64 { return self.epoch }

// Committer is the leaf that authored the commit.
func (self *StagedCommit) Committer() LeafIndex { return self.committer }

// AddedLeaves is where the commit's Add proposals landed, in the order they were applied.
func (self *StagedCommit) AddedLeaves() []LeafIndex { return append([]LeafIndex(nil), self.added...) }

// RemovedLeaves is the leaves the commit blanked.
func (self *StagedCommit) RemovedLeaves() []LeafIndex {
	return append([]LeafIndex(nil), self.removed...)
}

// UpdatedLeaves is the leaves an Update proposal replaced.
func (self *StagedCommit) UpdatedLeaves() []LeafIndex {
	return append([]LeafIndex(nil), self.updated...)
}

// RemovesSelf reports whether this commit removes the processing client.
func (self *StagedCommit) RemovesSelf() bool { return self.selfRemoved }

// GroupContextExtensions is the post-commit extension list, as storage the caller owns.
//
// The BODIES are copied and not the entries alone, which is NewGroup's rule at the other end of the
// same list and is here for its reason: an Extension copied by value goes on pointing at the octets
// the new epoch's group context was built over, so a caller that wrote through one would be
// rewriting the context this client is about to derive an epoch's secrets under.
func (self *StagedCommit) GroupContextExtensions() []Extension {
	if self.context.Extensions == nil {
		return nil
	}
	out := make([]Extension, 0, len(self.context.Extensions))
	for _, extension := range self.context.Extensions {
		out = append(out, Extension{
			ExtensionType: extension.ExtensionType,
			ExtensionData: cloneBytes(extension.ExtensionData),
		})
	}
	return out
}

// EpochAuthenticator is the new epoch's fork-detection value, as storage the caller owns.
func (self *StagedCommit) EpochAuthenticator() []byte {
	return cloneBytes(self.schedule.Secrets().EpochAuthenticator)
}
