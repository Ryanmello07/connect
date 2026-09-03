// The gates over the one thing (*ProposalList) now decides: that its per-type views ARE its commit
// order and cannot be given anything else.
//
// WHY THIS FILE EXISTS AND WHY IT IS NOT A THIRD CHECK. ProposalList used to carry the commit order
// and four per-type buckets as independently writable fields, and the two doors of this package
// read different ones -- apply_proposals.go walked Updates and Removes while every rule of
// validate_proposals.go read the buckets and the door held the two together by a per-type COUNT.
// Two rounds of gates were written against that shape and each left a live bypass, because every
// bypass came back in count-preserving form. Four of them were verified against the counting door:
//
//	All=[remove(committer)]                    Removes=[remove(3)]     -> accepted, applies remove 3
//	All=[add colliding with the path leaf key]  Adds=[innocent]        -> accepted
//	All=[update publishing the path leaf key]   Updates=[innocent]     -> accepted
//	All=[gce installing an unlisted extension]  GCE=[the good set]     -> accepted
//
// The first is the one to sit with: the sender signed a self-remove and the receiver removed leaf
// 3. That is one member applying a different commit from the one the transcript covers, with every
// count equal.
//
// The repair is not another rule. The views are derived from the commit order at every read, so
// none of those four inputs can be BUILT: whatever the order says, the view says. This file drives
// exactly that, in three shapes -- the type keeps its proposals in one place, every view is the
// order filtered element by element, and each of the four bypasses is now refused by the aggregate
// that used to accept it -- plus the measurement that says what the derivation costs, because the
// alternative to deriving is caching and a cache is a second representation again.
package mls

import (
	"errors"
	"go/ast"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"
	"unicode"
)

// ---------------------------------------------------------------------------
// one representation
// ---------------------------------------------------------------------------

// proposalListStorageFields is every field of ProposalList that can hold cached proposals, by any
// route the type system offers.
//
// BY ROUTE AND NOT BY TYPE NAME, which is rule 5 at the one place it has to hold here. A gate that
// looked for []CachedProposal fields would pass a `map[ProposalType][]CachedProposal` index built
// beside the order -- which is exactly the cache the derivation was chosen over, and exactly the
// shape a later edit reaches for when it decides the filtering is too expensive. So the walk
// follows slices, arrays, pointers and map values down to the element type.
//
// It does not descend into struct fields, which bounds the walk: a CachedProposal carries a
// Proposal carrying arm pointers, and a walk into those would recurse over the whole wire model
// answering nothing.
func proposalListStorageFields(t *testing.T) []reflect.StructField {
	t.Helper()
	entry := reflect.TypeOf(CachedProposal{})
	var carries func(reflect.Type) bool
	carries = func(held reflect.Type) bool {
		if held == entry {
			return true
		}
		switch held.Kind() {
		case reflect.Slice, reflect.Array, reflect.Pointer, reflect.Map:
			return carries(held.Elem())
		}
		return false
	}
	found := []reflect.StructField{}
	structure := reflect.TypeOf(ProposalList{})
	for i := 0; i < structure.NumField(); i += 1 {
		if carries(structure.Field(i).Type) {
			found = append(found, structure.Field(i))
		}
	}
	return found
}

// TestAProposalListKeepsItsProposalsInExactlyOnePlace is the unrepresentability claim itself.
//
// ONE FIELD, AND IT IS UNEXPORTED. Both halves are the property. A second field holding cached
// proposals is a second representation of one fact whatever it is called and whatever rule is
// stood over it -- an Adds bucket, or an index keyed by type -- and that is the class this type
// was rebuilt to remove. An EXPORTED field is one a caller outside this package writes, which is
// how the four bypasses above were built in the first place.
//
// A cache would fail this, deliberately. Filtering at every read costs something and the honest
// alternative is to index once at construction and answer the index; that index cannot diverge
// from the order for a caller, but it can diverge for an in-package edit, and it re-opens the
// exact question two rounds of gates failed to close. What it would buy is measured by
// TestDerivingTheViewsCostsLessThanTheRulesThatReadThem, which is why the measurement is in the
// suite rather than in a commit message.
func TestAProposalListKeepsItsProposalsInExactlyOnePlace(t *testing.T) {
	fields := proposalListStorageFields(t)
	if len(fields) != 1 {
		names := []string{}
		for _, field := range fields {
			names = append(names, field.Name+" "+field.Type.String())
		}
		t.Fatalf("ProposalList holds cached proposals in %d fields, %v; one fact in two fields is two representations with no identity relation between them, which is the defect this type was rebuilt to remove rather than to check for",
			len(fields), names)
	}
	held := fields[0]
	if want := reflect.TypeOf([]CachedProposal{}); held.Type != want {
		t.Errorf("ProposalList keeps its proposals in a %s; the commit order is a sequence and section 12.1.1 places adds in it, so anything that is not a %s has lost the order",
			held.Type, want)
	}
	if unicode.IsUpper([]rune(held.Name)[0]) {
		t.Errorf("ProposalList keeps its proposals in the exported field %s; a caller outside this package can then write it, and a caller writing one field of a list is the whole of how a commit came to be validated as one thing and applied as another",
			held.Name)
	}
	// and the views really are answered by methods rather than by that field under another name
	views := proposalListViewMethods(t)
	if len(views) == 0 {
		t.Fatal("*ProposalList answers no per-type view, so the field above is the only way to read a list and every rule of section 12.2 would be reading it directly")
	}
}

// ---------------------------------------------------------------------------
// every view is the commit order filtered
// ---------------------------------------------------------------------------

// testInterleavedCommitOrder is a commit order carrying TWO proposals of every viewed type, no two
// of one type adjacent, each entry marked with a Sender nothing else in the order shares.
//
// THE MARK IS WHAT MAKES THE COMPARISON AN IDENTITY. Two removes of the same leaf are equal values,
// so a view that answered the right COUNT of the right TYPE in the wrong ORDER -- or that answered
// some other remove of the list -- would compare equal to the filter under any comparison of
// counts or of types. Sender is carried straight through by every accessor and is not read by any
// of them, so it is a serial number this test can put on each entry and find again.
//
// TWO OF EACH and interleaved, because one of each cannot tell an ordered filter from a filter that
// answers whatever it finds first, and a contiguous run cannot tell a filter from a slice of the
// order.
func testInterleavedCommitOrder(t *testing.T) []CachedProposal {
	t.Helper()
	viewed := []ProposalType{}
	for _, bucket := range proposalBucketsOf(&ProposalList{}) {
		viewed = append(viewed, bucket.carries)
	}
	if len(viewed) < 2 {
		t.Fatalf("a ProposalList answers %d views; with fewer than two, an interleaving is one type in a row and this fixture separates nothing",
			len(viewed))
	}
	order := []CachedProposal{}
	for round := 0; round < 2; round += 1 {
		for _, carries := range viewed {
			order = append(order, CachedProposal{
				Proposal: Proposal{ProposalType: carries},
				Sender:   LeafIndex(len(order)),
				ByValue:  true,
			})
		}
	}
	return order
}

// TestEveryPerTypeViewOfAProposalListIsItsCommitOrderFiltered is the identity relation, driven
// element by element over the derived class of views.
//
// ELEMENT BY ELEMENT AND NOT BY COUNT, which is the whole difference between this and the rule it
// replaces. validateBucketsAgreeWithTheCommitOrder compared len(bucket) with the number of entries
// of that type in the order, and every input that got past it satisfied that comparison: an entry
// swapped for another of its type, a bucket reordered, a bucket holding somebody else's proposals
// of the right type. Each of those is a different sequence with the same length, so what is
// compared here is the sequence.
//
// BOTH DIRECTIONS OF THE CLASS. The views are read off *ProposalList's method set and each is
// joined to the type it filters on through proposalBucketsOf, so a view whose accessor filters on
// the WRONG type fails here rather than answering a plausible-looking slice, and a fifth view added
// later is driven on the commit that adds it.
func TestEveryPerTypeViewOfAProposalListIsItsCommitOrderFiltered(t *testing.T) {
	order := testInterleavedCommitOrder(t)
	list := NewProposalList(order)
	if len(list.All()) != len(order) {
		t.Fatalf("the list answers %d entries in its commit order and was built from %d",
			len(list.All()), len(order))
	}
	carriedBy := map[string]ProposalType{}
	for _, bucket := range proposalBucketsOf(list) {
		carriedBy[bucket.accessor] = bucket.carries
	}
	views := proposalListViewMethods(t)
	if len(views) == 0 {
		t.Fatal("*ProposalList answers no per-type view, so this compared nothing")
	}
	covered := 0
	for _, method := range views {
		carries, joined := carriedBy[method.Name]
		if !joined {
			t.Errorf("*ProposalList answers %s and proposalBucketsOf says nothing about which type it filters on; a view nobody can name the type of is a view no gate can say is the right one",
				method.Name)
			continue
		}
		// the filter this view is CLAIMED to be, computed here off the commit order the list was
		// built from rather than off anything the list answers
		want := []LeafIndex{}
		for _, entry := range order {
			if entry.Proposal.ProposalType == carries {
				want = append(want, entry.Sender)
			}
		}
		if len(want) == 0 {
			t.Errorf("the fixture carries no %s, so the %s view is compared against an empty sequence and would agree with anything that answered nothing",
				proposalTypeName(carries), method.Name)
			continue
		}
		answered := reflect.ValueOf(list).MethodByName(method.Name).Call(nil)[0].
			Interface().([]CachedProposal)
		got := []LeafIndex{}
		for _, entry := range answered {
			if entry.Proposal.ProposalType != carries {
				t.Errorf("the %s view answered a %s; the view is not the commit order filtered on %s at all",
					method.Name, proposalTypeName(entry.Proposal.ProposalType),
					proposalTypeName(carries))
			}
			got = append(got, entry.Sender)
		}
		if !slices.Equal(got, want) {
			t.Errorf("the %s view answers the entries %v of the commit order and the order's %s proposals are %v; a view that is not that sequence is a second representation of the commit, and the rules stated over it are rules about a commit nobody sent",
				method.Name, got, proposalTypeName(carries), want)
		}
		covered += 1
	}
	t.Logf("%d per-type views, each held to the commit order element by element over %d entries",
		covered, len(order))
}

// TestAViewOfAProposalListFollowsAWriteToTheCommitOrder is the half of the property a comparison of
// two sequences cannot make.
//
// The test above compares what a view answers with what the order holds AT ONE MOMENT, and an
// index built once at construction agrees with it exactly. What separates a derivation from an
// index is what happens after the order changes: a derived view answers the new order, an index
// answers the order it was built from. This is that, and it is the reason the accessors filter at
// the read rather than caching.
//
// The write goes through All(), which answers the list's own vector rather than a copy -- so this
// also holds that door open. A version of All() that cloned would make this test pass for the
// wrong reason, and the assertion below is written over what the VIEW answers rather than over
// what All answers, so a clone breaks it.
func TestAViewOfAProposalListFollowsAWriteToTheCommitOrder(t *testing.T) {
	list := NewProposalList(testInterleavedCommitOrder(t))
	removes := list.Removes()
	if len(removes) < 2 {
		t.Fatalf("the fixture's commit order carries %d removes; with fewer than two there is no entry to change that is not the first",
			len(removes))
	}
	// the SECOND remove of the order, found through the order rather than through the view: a
	// write through the view is a write to a slice the view built, which is the mistake this
	// function exists to be the counter-example of
	at := -1
	seen := 0
	order := list.All()
	for i := range order {
		if order[i].Proposal.ProposalType != ProposalTypeRemove {
			continue
		}
		if seen == 1 {
			at = i
			break
		}
		seen += 1
	}
	if at < 0 {
		t.Fatal("the commit order does not carry a second remove, so nothing below is written")
	}
	const marked = LeafIndex(0x5eed)
	order[at].Sender = marked
	if answered := list.Removes(); len(answered) < 2 || answered[1].Sender != marked {
		t.Fatalf("the commit order's second remove was changed and the removes view answers %v; a view that does not follow the order is an index built once, which is the second representation this type was rebuilt to stop having",
			answered)
	}
	// and the other views are unaffected, so what followed was the entry rather than the whole
	for _, bucket := range proposalBucketsOf(list) {
		if bucket.carries == ProposalTypeRemove {
			continue
		}
		for _, entry := range bucket.entries {
			if entry.Sender == marked {
				t.Errorf("the %s view answers the entry that was written into the removes of the commit order; a view answering another type's entries filters on nothing",
					bucket.accessor)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// the four inputs the counting door accepted
// ---------------------------------------------------------------------------

// commitBypass is one of the four count-preserving disagreements the per-type COUNT rule admitted,
// as an edit to the commit order of a commit ValidateCommit accepts.
//
// EACH EDIT IS A SWAP AND NOT A DELETION. The entry at one position of the order is exchanged for
// another proposal of the same type at the same position, so the total count, every per-type count
// and the commit's own ProposalOrRef vector are all unchanged -- which is precisely the class the
// count rule could not see, and precisely the class the derivation makes unrepresentable.
type commitBypass struct {
	// view is the per-type view the old bucket field would have carried the innocent entry in.
	view string
	// swaps replaces the entry that view answers first with the offending one, in place, in the
	// commit order.
	swaps func(t *testing.T, in *CommitValidationInput)
	// refuses is what the aggregate must answer now that the view cannot be given anything else.
	refuses error
}

// commitBypassesTheCountRuleAdmitted is the four inputs the owner verified against the counting
// door, each of which it returned nil for.
func commitBypassesTheCountRuleAdmitted() map[string]commitBypass {
	return map[string]commitBypass{
		"a remove of the committer behind an innocent remove": {
			view: "Removes",
			swaps: func(t *testing.T, in *CommitValidationInput) {
				testListEntryAt(t, in.List, "Removes", 0).Proposal.Remove.Removed = in.Committer
			},
			refuses: ErrRemoveCommitter,
		},
		"an add republishing the update path's leaf key": {
			view: "Adds",
			swaps: func(t *testing.T, in *CommitValidationInput) {
				testListEntryAt(t, in.List, "Adds", 0).Proposal.Add.KeyPackage.LeafNode.EncryptionKey =
					in.Commit.Path.LeafNode.EncryptionKey
			},
			refuses: errDuplicateEncryptionKey,
		},
		"an update republishing the update path's leaf key": {
			view: "Updates",
			swaps: func(t *testing.T, in *CommitValidationInput) {
				testListEntryAt(t, in.List, "Updates", 0).Proposal.Update.LeafNode.EncryptionKey =
					in.Commit.Path.LeafNode.EncryptionKey
			},
			refuses: errDuplicateEncryptionKey,
		},
		"a group_context_extensions installing an extension outside the v1 profile": {
			view: "GCE",
			swaps: func(t *testing.T, in *CommitValidationInput) {
				// 0xABCD, which is the code point the owner used against the counting door: a
				// type this build's extension registry does not carry, so no member could
				// evaluate it and the group would be agreeing to a state none of them can read
				installed := append(slices.Clone(testCommitInstalledExtensions()),
					Extension{ExtensionType: ExtensionType(0xABCD), ExtensionData: []byte{}})
				testListEntryAt(t, in.List, "GCE", 0).Proposal.GroupContextExtensions.Extensions =
					installed
			},
			refuses: errUnregisteredGroupExtension,
		},
	}
}

// TestTheCountPreservingBypassesOfTheBucketJoinCannotBeBuilt drives all four, and drives the
// reason they are gone rather than caught.
//
// THREE ASSERTIONS PER ROW, and the middle one is the one that says the bypass is unrepresentable
// rather than refused by a third count. First the unedited commit is ACCEPTED, so what follows is
// the edit's answer and not the fixture's. Then the view the old bucket field would have carried
// the innocent entry in is required to ANSWER THE OFFENDING ENTRY: under the old type this was the
// step a caller skipped, by leaving the innocent proposal in the bucket and the offending one in
// All, and there is now no field to leave it in. Then the aggregate refuses.
//
// A rule that read the commit order and a rule that read a bucket used to be two rules about two
// commits. They are now two spellings of one rule about one commit, and that is what each row here
// measures.
func TestTheCountPreservingBypassesOfTheBucketJoinCannotBeBuilt(t *testing.T) {
	crypto := testCrypto(t)
	rows := commitBypassesTheCountRuleAdmitted()
	// one row per view, in both directions, so a fifth view is not a bypass nobody wrote a row for
	views := proposalListBucketNames(t)
	covered := []string{}
	for _, row := range rows {
		covered = append(covered, row.view)
	}
	slices.Sort(covered)
	if !slices.Equal(covered, views) {
		t.Errorf("*ProposalList answers the views %v and the bypasses here cover %v; a view with no row is one nothing says a commit cannot be judged through and applied around",
			views, covered)
	}
	for _, name := range slices.Sorted(maps.Keys(rows)) {
		row := rows[name]
		t.Run(name, func(t *testing.T) {
			in := testCommitCarryingOneOfEveryBucket(t, crypto)
			if failure := ValidateCommit(in); failure != nil {
				t.Fatalf("ValidateCommit refused the commit this row is one swap away from: %v; every refusal below would then be that one",
					failure)
			}
			before := len(in.List.All())
			counts := map[string]int{}
			for _, bucket := range proposalBucketsOf(in.List) {
				counts[bucket.accessor] = len(bucket.entries)
			}
			row.swaps(t, in)
			// the swap preserved every count the retired rule could see, which is what makes this
			// the input that rule admitted rather than one it would have caught
			if after := len(in.List.All()); after != before {
				t.Fatalf("the swap changed the commit order from %d entries to %d; it is a deletion and not the count-preserving edit this row is about",
					before, after)
			}
			for _, bucket := range proposalBucketsOf(in.List) {
				if got := len(bucket.entries); got != counts[bucket.accessor] {
					t.Fatalf("the swap changed the %s view from %d entries to %d; the retired count rule would have caught this input, so it is not the one that got past it",
						bucket.accessor, counts[bucket.accessor], got)
				}
			}
			// and the view the innocent entry used to hide in answers the offending entry, which
			// is the whole of the repair: there is no field left to hide it in
			answered := false
			for _, bucket := range proposalBucketsOf(in.List) {
				if bucket.accessor != row.view {
					continue
				}
				answered = len(bucket.entries) > 0
			}
			if !answered {
				t.Fatalf("the %s view answers nothing after the swap, so the rule stated over it reads nothing and this row asserts a refusal that came from somewhere else",
					row.view)
			}
			if failure := ValidateCommit(in); !errors.Is(failure, row.refuses) {
				t.Fatalf("ValidateCommit over the swapped commit answered %v, want %v; this is the input the counting door returned nil for, and a member that accepts it applies a commit the transcript does not cover",
					failure, row.refuses)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// what the derivation costs
// ---------------------------------------------------------------------------

// proposalListViewReadsOfSectionTwelveTwo is how many times each per-type view is filtered during
// one run of ValidateProposalList, read off validate_proposals.go rather than counted by hand.
//
// OFF THE SOURCE, because the number is the point of the measurement: the cost of deriving is the
// cost of one filter multiplied by how many the rules ask for, and a hand-written number would be
// the thing that goes stale the moment a rule is added. Every rule binds its view once and ranges
// over the binding -- ranging over the call would refilter at every index, which is the one shape
// this package must not have -- so the calls are what to count.
func proposalListViewReadsOfSectionTwelveTwo(t *testing.T) map[string]int {
	t.Helper()
	parsed := mustParseSource(t, "validate_proposals.go")
	reads := map[string]int{}
	for _, bucket := range proposalBucketsOf(&ProposalList{}) {
		reads[bucket.accessor] = 0
	}
	ast.Inspect(parsed.file, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall || len(call.Args) != 0 {
			return true
		}
		selector, isSelector := call.Fun.(*ast.SelectorExpr)
		if !isSelector {
			return true
		}
		if _, named := reads[selector.Sel.Name]; !named {
			return true
		}
		base := parsed.render(selector.X)
		if base != "in.List" && base != "list" {
			return true
		}
		reads[selector.Sel.Name] += 1
		return true
	})
	return reads
}

// testFullValidationInput is a section 12.2 input carrying a list of every viewed type at the width
// this profile's fixtures can build, and one ValidateProposalList ACCEPTS.
//
// Accepted, which is what makes the timing below a timing of the whole aggregate: every rule
// returns the first failure, so a list any rule refuses is a measurement of the rules that ran
// before it. The list is a commit from leaf 0 that updates the first third of the members, removes
// the last third and adds a handful, which is a shape section 12.2 admits -- updates and removes
// apply to disjoint leaves, no leaf is named twice, and the committer is neither updated nor
// removed.
func testFullValidationInput(t *testing.T, crypto CryptoProvider,
	members int) *ProposalValidationInput {

	t.Helper()
	names := []string{}
	for at := 0; at < members; at += 1 {
		names = append(names, "member-"+strconv.Itoa(at))
	}
	tree, built := testTreeWith(t, crypto, names...)
	third := members / 3
	entries := []CachedProposal{}
	for at := 1; at <= third; at += 1 {
		update, _ := testUpdateProposalOf(t, crypto, built[at], LeafIndex(at))
		entries = append(entries, update)
	}
	for at := members - third; at < members; at += 1 {
		entries = append(entries, testRemoveOf(LeafIndex(at)))
	}
	for at := 0; at < third; at += 1 {
		kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "joiner-"+strconv.Itoa(at)))
		entries = append(entries, testAddOf(kp))
	}
	entries = append(entries, testGceOf(Extension{
		ExtensionType: ExtensionTypeUrmessageGroupPolicy, ExtensionData: []byte{0x01}}))
	return testValidationInput(t, crypto, tree, LeafIndex(0), testProposalList(t, entries...))
}

// TestDerivingTheViewsCostsLessThanTheRulesThatReadThem is the measurement the choice between
// deriving and caching turns on, run in the suite rather than quoted from a commit message.
//
// THE QUESTION. A per-type view is the commit order filtered at every read, and section 12.2 reads
// the views a fixed number of times per validation -- counted off the source above, not here. The
// honest alternative is an index built once at construction, which is a second representation of
// the same proposals: unwritable by a caller, but able to fall behind an in-package write to the
// order it was built from, which is the question two rounds of gates already failed to close. It is
// worth having only if the filtering is a material share of what a commit costs.
//
// THE ANSWER, on this tree at this width, is that it is not: the filtering is a small fraction of
// the aggregate that asks for it, and the aggregate is itself run once per epoch. So the bound
// here is loose on purpose -- what it is protecting against is not a few percent of drift but a
// change of ORDER, an accessor that came to be called inside a loop, or a view built by something
// quadratic. Either of those would put the filtering above the rules and fail this.
//
// The two halves are timed over the same list in the same process, so the number compared is a
// ratio rather than a wall clock somebody would have to normalise.
func TestDerivingTheViewsCostsLessThanTheRulesThatReadThem(t *testing.T) {
	crypto := testCrypto(t)
	const members = 96
	in := testFullValidationInput(t, crypto, members)
	if err := ValidateProposalList(in); err != nil {
		t.Fatalf("the fixture list is refused with %v, so the timing below would be a timing of the rules that ran before the refusal",
			err)
	}
	reads := proposalListViewReadsOfSectionTwelveTwo(t)
	asked := 0
	for _, count := range reads {
		asked += count
	}
	if asked == 0 {
		t.Fatal("the scan found no view read in validate_proposals.go, so the derived half below replays nothing")
	}
	if entries := len(in.List.All()); entries < members/2 {
		t.Fatalf("the fixture's commit order carries %d entries over %d members; a filter measured over a short list is a measurement of the call and not of the walk",
			entries, members)
	}

	const rounds = 50
	// the whole of section 12.2, which is what the views are read BY
	whole := time.Now()
	for round := 0; round < rounds; round += 1 {
		if err := ValidateProposalList(in); err != nil {
			t.Fatalf("the fixture stopped being accepted mid-measurement: %v", err)
		}
	}
	wholeTook := time.Since(whole)

	// and exactly the view reads that aggregate makes, replayed off the counted class
	views := time.Now()
	filtered := 0
	for round := 0; round < rounds; round += 1 {
		for _, bucket := range proposalBucketsOf(in.List) {
			for at := 0; at < reads[bucket.accessor]; at += 1 {
				filtered += len(bucket.entries)
			}
		}
	}
	viewsTook := time.Since(views)
	if filtered == 0 {
		t.Fatal("the replay filtered nothing, so the half below is a timing of an empty loop")
	}

	share := float64(viewsTook) / float64(wholeTook)
	t.Logf("section 12.2 over %d proposals: %v for the whole aggregate, %v for the %d view reads it makes (%v), %.1f%% of it",
		len(in.List.All()), wholeTook/rounds, viewsTook/rounds, asked, reads, share*100)
	// half, which is loose by design: what fails this is a change of order rather than drift
	if share > 0.5 {
		t.Errorf("filtering the views costs %.1f%% of what the rules that read them cost; the derivation was chosen over an index on the measurement that it does not, so either the accessors have become quadratic or a rule has started filtering inside a loop",
			share*100)
	}
}
