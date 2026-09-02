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
