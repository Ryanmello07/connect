// The gate over RFC 9420 section 12.4's path-required rule, at the entry point the commit
// lifecycle asks it through.
package mls

import (
	"bytes"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// TestCommitPathRequiredRules is the plan's four cases, plus the two the plan's four cannot see.
//
// The plan states the rule with one path-required proposal in each list and with that proposal at
// index 0 in three of the four. A rule that answered `proposalTypePathRequired(All[0])` passes all
// four of them, because the one case whose offender is not at index zero -- an add followed by an
// update -- is the case the plan happens to write second. That is the p4 ValSem401 shape this
// package has shipped four times, so the offender is walked to the LAST index of a longer list
// here rather than left where a hand written fixture put it.
func TestCommitPathRequiredRules(t *testing.T) {
	empty := &ProposalList{}
	if !CommitPathRequired(empty) {
		t.Fatal("an empty proposal list requires a path")
	}

	addOnly := &ProposalList{All: []CachedProposal{
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
	}}
	if CommitPathRequired(addOnly) {
		t.Fatal("an add-only list does not require a path")
	}

	withUpdate := &ProposalList{All: []CachedProposal{
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeUpdate}},
	}}
	if !CommitPathRequired(withUpdate) {
		t.Fatal("a list containing an update requires a path")
	}

	withGce := &ProposalList{All: []CachedProposal{
		{Proposal: Proposal{ProposalType: ProposalTypeGroupContextExtensions}},
	}}
	if !CommitPathRequired(withGce) {
		t.Fatal("group_context_extensions is in the RFC 9420 section 12.4 pathRequiredTypes list")
	}

	// the case the plan's four do not hold: the only path-required entry sits at the END of a
	// list of four, behind three that are not.
	trailing := &ProposalList{All: []CachedProposal{
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeRemove}},
	}}
	if !CommitPathRequired(trailing) {
		t.Fatal("a remove at the last index of a four entry list requires a path; the rule is over every entry and not over the first")
	}

	// a list with no path-required entry ANYWHERE is the other half of that: a rule that
	// answered true for any non-empty list would pass every case above.
	if CommitPathRequired(&ProposalList{All: []CachedProposal{
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
	}}) {
		t.Fatal("four adds require no path")
	}
}

// TestCommitPathRequiredIsThePathRequiredTypeSetOverTheWholeRegistry holds the entry point to the
// RFC's type set rather than to a list written here.
//
// The class is this package's own ProposalType constants, read out of the source, so a ninth code
// point registered later is swept on the commit that declares it. What is asserted is that a
// singleton list of each type agrees with proposalTypePathRequired -- which is where section
// 12.4's four names are transcribed -- so a CommitPathRequired that quietly consulted some other
// set fails here rather than at whichever type the fixtures above happen not to use.
func TestCommitPathRequiredIsThePathRequiredTypeSetOverTheWholeRegistry(t *testing.T) {
	declared := registryConstantsOfType(t, "ProposalType")
	if len(declared) == 0 {
		t.Fatal("this package declares no ProposalType constant, so the sweep below reads nothing")
	}
	agreed := 0
	required := 0
	for _, name := range slices.Sorted(maps.Keys(declared)) {
		proposalType := ProposalType(declared[name])
		list := &ProposalList{All: []CachedProposal{{Proposal: Proposal{ProposalType: proposalType}}}}
		want := proposalTypePathRequired(proposalType)
		if got := CommitPathRequired(list); got != want {
			t.Errorf("CommitPathRequired over a list of one %s = %v, and proposalTypePathRequired says %v",
				name, got, want)
			continue
		}
		agreed += 1
		if want {
			required += 1
		}
	}
	// both halves have to be non empty or the sweep is satisfied by a constant answer
	if required == 0 || agreed-required == 0 {
		t.Fatalf("the registry sweep saw %d agreeing types of which %d require a path; a sweep whose expectation is the same for every member states nothing",
			agreed, required)
	}
	t.Logf("%d registered proposal types swept, %d of them path-required", agreed, required)
}

// TestCommitPathRequiredAnswersTrueForANilList states the fail-closed direction.
//
// A nil list reaches this from a caller that has not resolved a commit's ProposalOrRef vector
// yet, and the answer that costs nothing is "a path is required": section 12.4's empty clause
// already says a commit naming no proposals must carry one. The other answer is a validator that
// lets a pathless commit through because its caller forgot an argument.
func TestCommitPathRequiredAnswersTrueForANilList(t *testing.T) {
	if !CommitPathRequired(nil) {
		t.Fatal("CommitPathRequired(nil) = false; a caller that handed over no list is asking about a commit that names no proposals, and section 12.4 requires a path for one of those")
	}
}

// TestCommitCodecIsTheFramingPlans is the plan's own assertion that this task declares no codec:
// the commit bytes are load bearing for the confirmed transcript hash, so the round trip is
// asserted through the single byte-level entry points rather than through anything here.
//
// commit_wire_test.go holds the same three properties over its own fixtures. This is kept because
// it is the assertion this file makes about OWNERSHIP -- that syntax.Marshal of a Commit built
// here is the framing plan's encoding and not a second one -- and because a task that added a
// codec beside the rule would pass every test in that file.
func TestCommitCodecIsTheFramingPlans(t *testing.T) {
	commit := &Commit{Proposals: []ProposalOrRef{{
		Type:     ProposalOrRefTypeProposal,
		Proposal: &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 2}},
	}}}
	encoded, err := syntax.Marshal(commit)
	if err != nil {
		t.Fatalf("syntax.Marshal: %v", err)
	}
	if encoded[len(encoded)-1] != 0x00 {
		t.Fatalf("absent path must encode as the 0x00 optional presence byte, got %#x", encoded[len(encoded)-1])
	}
	var parsed Commit
	if err := syntax.Unmarshal(encoded, &parsed); err != nil {
		t.Fatalf("syntax.Unmarshal: %v", err)
	}
	if parsed.Path != nil {
		t.Fatal("Path must be nil when the presence byte is 0")
	}
	reencoded, err := syntax.Marshal(&parsed)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatal("re-encode is not byte identical")
	}

	// 0x02 is not a legal optional presence byte: two encodings of "absent" would be a
	// signature-bypass primitive.
	mutated := append([]byte(nil), encoded...)
	mutated[len(mutated)-1] = 0x02
	if err := syntax.Unmarshal(mutated, &parsed); err == nil {
		t.Fatal("syntax.Unmarshal accepted presence byte 0x02")
	}
	if err := syntax.Unmarshal(append(encoded, 0xFF), &parsed); !errors.Is(err, syntax.ErrTrailingBytes) {
		t.Fatalf("syntax.Unmarshal with a trailing byte = %v, want ErrTrailingBytes", err)
	}
}
