// RFC 9420 section 12.3, applying a proposal list to a ratchet tree and a group context.
//
// THE ORDER HERE IS NORMATIVE AND IT IS THE WHOLE OF WHAT THIS FILE DECIDES. Section 12.3 fixes
// it: GroupContextExtensions first, then Updates in any order, then Removes in any order, then
// Adds IN THE ORDER THEY APPEAR IN THE LIST. Each of those clauses is a fork if it is got wrong,
// and none of them is visible from a list that happens to be sorted.
//
//   - Adds last, because section 12.1.1 places an added member at the leftmost blank leaf. A
//     Remove applied after an Add fills a different gap than the same Remove applied before it, so
//     the two orders build different trees, different tree hashes and different confirmed
//     transcripts -- a split, not an error.
//   - Adds in LIST order rather than in bucket order, for the same reason at one level down: two
//     commits carrying the same set of adds in a different order place those members on different
//     leaves. This is why ProposalList keeps All beside its buckets at all.
//   - GroupContextExtensions first, because section 12.3 says the new extensions MUST be used when
//     evaluating the rest of the list -- a required_capabilities added by the same commit is a
//     requirement its own Adds have to meet.
//
// An implementation that walked the list in commit order passes every test whose list happens to
// be sorted remove-then-add, which is what most fixtures look like.
// TestApplyProposalsAppliesTheRfcOrderAndNotTheListOrder is built the other way round on purpose.
//
// THIS TAKES NO CryptoProvider, and that is the one place this file's signature is not the plan's.
// The plan pins ApplyProposals(crypto, tree, ctx, own, list) and justifies the provider by
// (*RatchetTree).TreeHash -- which section 12.3 does not compute, and which section 12.4.2 computes
// only AFTER the update path has been merged, so a hash taken here would be a field nothing reads.
// A provider parameter no body reaches is not free in this package: package level constructions
// taking a CryptoProvider are a class the crypto gates derive off the type checker, and every one
// of them is called, perturbed and required to answer differently for each argument it was handed.
// Getting this one through them takes four base arguments, two perturbation rules and two
// exemptions, and the exemptions read "this construction answers nothing the gate can read and
// reaches no provider" -- which is the finding TestProviderHasNoRemainingStubs exists to make,
// written down as an excuse. So the parameter is dropped rather than excused, and the callers the
// plan writes for tasks 22, 23 and 25 pass one argument fewer.
package mls

import (
	"fmt"
	"slices"
)

// ApplyResult is the post-proposal state, on a tree the caller did not own before this call.
//
// The three index vectors are answered in the order the operations happened, which is what makes
// AddedLeaves readable as "the first Add of the commit landed here". A commit's Welcome is
// addressed to them in that order.
type ApplyResult struct {
	Tree          *RatchetTree
	Extensions    []Extension
	AddedLeaves   []LeafIndex
	RemovedLeaves []LeafIndex
	UpdatedLeaves []LeafIndex
	SelfRemoved   bool
}

// ApplyProposals clones the tree and applies the list in the RFC 9420 section 12.3 order.
//
// THE CALLER'S TREE IS NEVER MUTATED, which is the second thing this file decides and is why the
// clone is the first statement rather than an optimisation the caller could skip. A commit is
// applied and then judged -- section 12.4.2 validates the update path, the tree and the
// confirmation tag against the tree this produces -- so a version that worked in place would
// leave a member's live state half-way through a commit it went on to reject, with no way back to
// the epoch it was in.
func ApplyProposals(tree *RatchetTree, ctx *GroupContext, own LeafIndex,
	list *ProposalList) (*ApplyResult, error) {

	if tree == nil {
		return nil, fmt.Errorf("%w: there is nothing to apply them to", errNilRatchetTree)
	}
	if ctx == nil {
		return nil, fmt.Errorf("%w: the extensions a GroupContextExtensions proposal replaces are its", ErrNilGroupContext)
	}
	if list == nil {
		return nil, fmt.Errorf("%w: there is nothing to apply", errNilProposalList)
	}

	// the two structural rules of validate_proposals.go, ahead of every dereference below. A
	// bucket holding a proposal of another type, or a proposal whose named arm is not the one
	// populated, is a nil dereference at `cached.Proposal.Remove.Removed` -- and a caller that
	// applies before it validates is the ordinary shape rather than a mistake, because section
	// 12.4.2 validates the tree this produces. The rules are called rather than restated so that
	// there is one statement of each.
	structural := &ProposalValidationInput{Tree: tree, Context: ctx, Committer: own, List: list}
	if err := ValSem113ProposalTypeSupported(structural); err != nil {
		return nil, err
	}
	if err := validateProposalBucketsHoldTheirOwnType(structural); err != nil {
		return nil, err
	}
	if err := validateBucketsAgreeWithTheCommitOrder(structural); err != nil {
		return nil, err
	}

	// slices.Clone of the extension vector and not the caller's own backing array, for the
	// reason the tree is cloned: an ApplyResult is a candidate state, and a candidate that
	// shared storage with the live one could not be discarded. The bodies inside each Extension
	// are still shared, which is what every extension accessor of this package already
	// documents -- what is copied is the vector a later append would otherwise write through.
	result := &ApplyResult{Tree: tree.Clone(), Extensions: slices.Clone(ctx.Extensions)}

	// 1. GroupContextExtensions, WHOLESALE replacement rather than a merge. Section 12.1.7 is a
	//    replacement, and a merge would make an extension impossible to remove.
	if exts, ok := list.Extensions(); ok {
		result.Extensions = slices.Clone(exts)
	}

	// 2. Updates, any order. The sender's leaf is replaced and its direct path is blanked, which
	//    section 12.1.2 requires and RatchetTree.UpdateLeaf does.
	for i := range list.Updates {
		cached := &list.Updates[i]
		if err := result.Tree.UpdateLeaf(cached.Sender, &cached.Proposal.Update.LeafNode); err != nil {
			return nil, fmt.Errorf("mls: applying the update at updates[%d] for leaf %d: %w",
				i, cached.Sender, err)
		}
		result.UpdatedLeaves = append(result.UpdatedLeaves, cached.Sender)
	}

	// 3. Removes, any order. RemoveLeaf blanks the path, blanks the leaf and truncates.
	for i := range list.Removes {
		leafIndex := list.Removes[i].Proposal.Remove.Removed
		if err := result.Tree.RemoveLeaf(leafIndex); err != nil {
			return nil, fmt.Errorf("mls: applying the remove at removes[%d] for leaf %d: %w",
				i, leafIndex, err)
		}
		result.RemovedLeaves = append(result.RemovedLeaves, leafIndex)
		if leafIndex == own {
			result.SelfRemoved = true
		}
	}

	// 4. Adds, IN COMMIT ORDER. The bucket is not the order: it is the order the proposals were
	//    bucketed in, which for a resolved list is the commit order and for a list a caller
	//    assembled is whatever that caller appended in. All is the field that carries the wire's
	//    own order, so the walk is over All and the Adds bucket is not read here at all.
	//    AddLeaf places at the leftmost blank leaf and extends the tree to the right when there
	//    is none.
	for i := range list.All {
		cached := &list.All[i]
		if cached.Proposal.ProposalType != ProposalTypeAdd {
			continue
		}
		leafIndex, err := result.Tree.AddLeaf(&cached.Proposal.Add.KeyPackage.LeafNode)
		if err != nil {
			return nil, fmt.Errorf("mls: applying the add at proposal %d of the commit order: %w", i, err)
		}
		result.AddedLeaves = append(result.AddedLeaves, leafIndex)
	}

	return result, nil
}
