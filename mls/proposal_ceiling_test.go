// What one epoch's proposal cache may hold, and the flood it used to hold instead.
//
// THE DEFECT THESE TESTS ARE ABOUT was measured rather than reasoned: 20,000 distinct well formed
// epoch 7 Remove proposals from ONE sender were all accepted, leaving len(byRef), len(order) and
// len(Pending()) at 20,000 apiece. Distinct is the load bearing word -- a ProposalRef is a hash over
// the whole AuthenticatedContent, so one byte of authenticated_data makes the same removal of the
// same leaf a new entry, and there is no semantic identity anywhere in the key. Nothing but Rebind
// empties the cache and Rebind runs at an epoch boundary, so a member who simply never commits keeps
// the epoch open and the map growing.
//
// And it was never only that member's memory. Pending answers EVERY entry, implementing RFC 9420
// section 12.4's "a committer includes all valid pending proposals" unconditionally, so an honest
// committer over a flooded cache emits a commit naming N references that every other member must
// already hold -- and anyone who missed one of them answers errProposalNotCached and cannot apply
// it. One flooding peer degrades the whole group, which is why the flood below is written as a test
// of what Pending answers and not only of what Store accepts.
//
// The scale here is the ceiling and not 20,000, because the ceiling is the number the property is
// about: at one under it every entry is one an honest member could have published, and at one over
// it the refusal is the whole of the fix. 20,000 would take longer and observe strictly less.
package mls

import (
	"encoding/binary"
	"errors"
	"maps"
	"slices"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// testFloodedProposalContent is one proposal of the fixture epoch made distinct from every other by
// ONE byte of authenticated_data and by nothing else.
//
// That is the reported attack verbatim. A flood built out of proposals that differ in their SUBJECT
// -- a remove of leaf 1, a remove of leaf 2 -- would be bounded by the group size whatever this
// cache did, and would let a wrong fix look right; a flood built out of one proposal re-stamped is
// bounded by nothing at all, because the reference is a hash over the octets and the octets differ.
func testFloodedProposalContent(t *testing.T, sender LeafIndex, nonce uint32,
	proposal *Proposal) *AuthenticatedContent {

	t.Helper()
	content := testProposalContentAt(t, sender, []byte("group"), 1, proposal)
	content.Content.AuthenticatedData = binary.BigEndian.AppendUint32(nil, nonce)
	return content
}

// testUpdateProposal is a well formed update carrying one member's signed leaf node.
func testUpdateProposal(t *testing.T, crypto CryptoProvider, member *testMember) *Proposal {
	t.Helper()
	leaf, _ := testLeafNode(t, crypto, member)
	return &Proposal{ProposalType: ProposalTypeUpdate, Update: &Update{LeafNode: *leaf}}
}

// testEnormousProposal is one group_context_extensions proposal just under the largest vector this
// codec will encode, which is the cheapest way to spend a mebibyte inside one accepted entry.
//
// It is what makes the point that an entry ceiling is not an octet ceiling: this is ONE entry
// against maxCachedProposals and about a thousandth of the entry ceiling, and about an eighth of
// everything the octet ceiling allows.
func testEnormousProposal() *Proposal {
	return &Proposal{
		ProposalType: ProposalTypeGroupContextExtensions,
		GroupContextExtensions: &GroupContextExtensions{Extensions: []Extension{{
			ExtensionType: ExtensionTypeRequiredCapabilities,
			ExtensionData: make([]byte, syntax.MaxVectorLength-64),
		}}},
	}
}

// ---------------------------------------------------------------------------
// the ceilings are derived from the accepted set, in both directions
// ---------------------------------------------------------------------------

// TestEveryProposalTypeTheV1ProfileAcceptsHasACeilingOfItsOwn holds the ceiling table EQUAL to the
// profile's accepted set, which is the shape the bucket rule beside it already takes.
//
// Both directions, and the reason is rule 5's. A fifth accepted type with no ceiling row would be
// admitted by checkCacheCeiling's lookup answering "no ceiling" -- which this build refuses, but
// only because that refusal exists; a table that merely listed four would leave the fifth type as
// the one this cache held without bound if anybody made the lookup permissive. And a ceiling for a
// type the profile no longer accepts is a row that outlived what it described, which is the defect
// this project's ledger names most often.
func TestEveryProposalTypeTheV1ProfileAcceptsHasACeilingOfItsOwn(t *testing.T) {
	accepted := []string{}
	for proposalType, refusal := range proposalTypeProfile {
		if refusal == nil {
			accepted = append(accepted, proposalTypeName(proposalType))
		}
	}
	if len(accepted) == 0 {
		t.Fatal("the v1 profile accepts no proposal type at all, so this gate compared two empty sets")
	}
	ceilinged := []string{}
	for proposalType := range proposalTypeCacheCeiling {
		ceilinged = append(ceilinged, proposalTypeName(proposalType))
	}
	slices.Sort(accepted)
	slices.Sort(ceilinged)
	if !slices.Equal(accepted, ceilinged) {
		t.Fatalf("the v1 profile accepts %v and the cache states a ceiling for %v; a type with no ceiling is one this cache would hold without bound, and a ceiling with no type is a row that outlived what it described",
			accepted, ceilinged)
	}
	for _, proposalType := range slices.Sorted(maps.Keys(proposalTypeCacheCeiling)) {
		ceiling := proposalTypeCacheCeiling[proposalType]
		if ceiling.perList < 1 || ceiling.perSender < 1 {
			t.Errorf("%s is accepted by the v1 profile and its ceiling is {perList:%d perSender:%d}; a ceiling below one refuses every proposal of a type the profile says it implements",
				proposalTypeName(proposalType), ceiling.perList, ceiling.perSender)
		}
		if ceiling.perSender > ceiling.perList {
			t.Errorf("%s allows one sender %d and the whole list %d; a per sender quota above the list ceiling is a quota nothing can spend and states a rule that never binds",
				proposalTypeName(proposalType), ceiling.perSender, ceiling.perList)
		}
	}
}

// TestTheEntryCeilingIsSummedOffTheCeilingTableRatherThanWrittenDown observes that the number and
// the table cannot drift.
//
// A written 1501 beside a table that grew a fifth row is a bound nobody updated, and it fails in the
// direction that matters: the cache would go on admitting entries a commit could not name.
//
// TWO ASSERTIONS AND THE SECOND IS THE ONE THAT HOLDS. Recomputing the sum off the same table today
// is satisfied by a body that returns the literal 1501, which is exactly the defect -- measured, and
// the reason the second half is here. So a row is ADDED to the ceiling table for the length of this
// test and the bound must move by that row. A written number does not move.
func TestTheEntryCeilingIsSummedOffTheCeilingTableRatherThanWrittenDown(t *testing.T) {
	summed := 0
	for proposalType, refusal := range proposalTypeProfile {
		if refusal != nil {
			continue
		}
		summed += proposalTypeCacheCeiling[proposalType].perList
	}
	if summed == 0 {
		t.Fatal("the accepted set summed to nothing, so this gate compared a bound against zero")
	}
	before := maxCachedProposals()
	if before != summed {
		t.Fatalf("maxCachedProposals() = %d and the per list column of the accepted set sums to %d; a bound that is not the sum of the table is one that stops describing it the moment the table changes",
			before, summed)
	}
	// and it is at least one per member, or a group at the profile's own membership cap could
	// not hold one pending proposal each and the ceiling would be refusing honest traffic
	if before < MaxGroupMembers {
		t.Errorf("maxCachedProposals() = %d and the v1 profile admits %d members; a cache that cannot hold one proposal per member refuses an honest epoch rather than a flood",
			before, MaxGroupMembers)
	}

	const widened = ProposalType(0x0D0D)
	if _, already := proposalTypeCacheCeiling[widened]; already {
		t.Fatalf("%#04x already has a ceiling, so this test is not modelling a widening at all", uint16(widened))
	}
	proposalTypeCacheCeiling[widened] = proposalCacheCeiling{perList: 7, perSender: 7}
	t.Cleanup(func() { delete(proposalTypeCacheCeiling, widened) })
	if got := maxCachedProposals(); got != before+7 {
		t.Fatalf("a ceiling row worth 7 was added to the table and maxCachedProposals() went from %d to %d, want %d; a bound written down rather than read off the table stops describing it the moment the table changes, and the direction it fails in is the permissive one",
			before, got, before+7)
	}
}

// ---------------------------------------------------------------------------
// the flood
// ---------------------------------------------------------------------------

// TestOneSenderCannotFloodOneEpochsCacheBeyondWhatOneCommitCouldName is the reported defect at the
// scale the property lives at, and it observes Pending rather than only Store.
//
// Pending is where the flood stopped being one member's problem: it answers every entry, so the
// number this asserts is the length of the reference vector an honest committer would put in a
// commit that every other member has to be able to resolve.
func TestOneSenderCannotFloodOneEpochsCacheBeyondWhatOneCommitCouldName(t *testing.T) {
	crypto := testCrypto(t)
	cache := testCache(t)
	ceiling := proposalTypeCacheCeiling[ProposalTypeRemove].perSender
	if ceiling < 2 {
		t.Fatalf("the remove ceiling is %d, so there is no one-under to observe", ceiling)
	}
	distinct := map[string]bool{}
	for i := 0; i < ceiling; i += 1 {
		ref, err := cache.Store(crypto, testResolveContext(),
			testFloodedProposalContent(t, LeafIndex(1), uint32(i), testRemoveProposal(LeafIndex(4))))
		if err != nil {
			t.Fatalf("Store of entry %d of the %d one valid commit list could carry from one sender: %v; every entry under the ceiling is one an honest member could have published",
				i, ceiling, err)
		}
		distinct[string(ref)] = true
	}
	if len(distinct) != ceiling {
		t.Fatalf("%d stores of one remove re-stamped produced %d distinct references, want %d; if they collide this test is not the flood it claims to be",
			ceiling, len(distinct), ceiling)
	}
	if held := len(cache.Pending(testResolveContext())); held != ceiling {
		t.Fatalf("Pending answers %d entries at the ceiling, want %d", held, ceiling)
	}

	// and one over
	_, err := cache.Store(crypto, testResolveContext(),
		testFloodedProposalContent(t, LeafIndex(1), uint32(ceiling), testRemoveProposal(LeafIndex(4))))
	if !errors.Is(err, errProposalCacheSenderQuota) {
		t.Fatalf("the %dth remove from one sender answered %v, want errProposalCacheSenderQuota; without it this cache holds whatever a peer sends and Pending hands all of it to a committer",
			ceiling+1, err)
	}
	if held := len(cache.Pending(testResolveContext())); held != ceiling {
		t.Fatalf("Pending answers %d entries after the refusal, want %d; a refusal that still counted the entry is a ceiling that moves",
			held, ceiling)
	}
}

// TestAFloodingSenderSpendsItsOwnQuotaAndNotTheGroups is why the per sender column exists at all.
//
// A cache capped only on its total is not safe, it is differently unsafe: the first sender to reach
// the total denies every honest member its own proposal for the rest of the epoch, which is the same
// availability failure the ceiling was added to prevent and is cheaper to mount than the memory one.
// So the property is not "a flood is refused" -- it is "a flood is refused and the next member is
// not".
func TestAFloodingSenderSpendsItsOwnQuotaAndNotTheGroups(t *testing.T) {
	crypto := testCrypto(t)
	cache := testCache(t)
	ceiling := proposalTypeCacheCeiling[ProposalTypeRemove].perSender
	for i := 0; i < ceiling; i += 1 {
		if _, err := cache.Store(crypto, testResolveContext(),
			testFloodedProposalContent(t, LeafIndex(1), uint32(i), testRemoveProposal(LeafIndex(4)))); err != nil {
			t.Fatalf("Store of flood entry %d: %v", i, err)
		}
	}
	if _, err := cache.Store(crypto, testResolveContext(),
		testFloodedProposalContent(t, LeafIndex(1), uint32(ceiling), testRemoveProposal(LeafIndex(4)))); !errors.Is(err, errProposalCacheSenderQuota) {
		t.Fatalf("the flooding sender was answered %v, want errProposalCacheSenderQuota", err)
	}
	if _, err := cache.Store(crypto, testResolveContext(),
		testFloodedProposalContent(t, LeafIndex(2), 0, testRemoveProposal(LeafIndex(5)))); err != nil {
		t.Fatalf("an honest member's first proposal was refused with %v while another member sat at its own quota; a ceiling counted only over the whole cache turns a flood into a lockout of everybody else",
			err)
	}
}

// TestTheSenderQuotaIsCountedPerTypeSoAnUpdateFloodStopsAtOne is section 12.2 read as a ceiling.
//
// An Update applies to its own sender's leaf, and a list carrying two proposals that apply to one
// leaf is invalid, so a sender's second update is a proposal no valid commit could carry beside its
// first however many it publishes. That makes the update flood the cheapest of the four to refuse,
// and it is refused at TWO rather than at the membership cap -- which is only visible if the quota
// is counted per type. A per sender total would let 500 updates through.
func TestTheSenderQuotaIsCountedPerTypeSoAnUpdateFloodStopsAtOne(t *testing.T) {
	crypto := testCrypto(t)
	member := testIdentity(t, crypto, "bob")
	cache := testCache(t)
	if got := proposalTypeCacheCeiling[ProposalTypeUpdate].perSender; got != 1 {
		t.Fatalf("the update ceiling allows one sender %d; section 12.2 invalidates a list carrying two proposals that apply to one leaf, and an update applies to its sender's own",
			got)
	}
	if _, err := cache.Store(crypto, testResolveContext(),
		testFloodedProposalContent(t, LeafIndex(1), 0, testUpdateProposal(t, crypto, member))); err != nil {
		t.Fatalf("the first update from a member was refused with %v", err)
	}
	if _, err := cache.Store(crypto, testResolveContext(),
		testFloodedProposalContent(t, LeafIndex(1), 1, testUpdateProposal(t, crypto, member))); !errors.Is(err, errProposalCacheSenderQuota) {
		t.Fatalf("a second update from one member answered %v, want errProposalCacheSenderQuota", err)
	}
	// the quota is that member's holding of that TYPE and not its holding of anything
	if _, err := cache.Store(crypto, testResolveContext(),
		testFloodedProposalContent(t, LeafIndex(1), 2, testRemoveProposal(LeafIndex(4)))); err != nil {
		t.Fatalf("a remove from a member at its update quota was refused with %v; the quota is counted per type, and one counted per sender alone would refuse it",
			err)
	}
	// and it is that MEMBER's holding and not the group's
	if _, err := cache.Store(crypto, testResolveContext(),
		testFloodedProposalContent(t, LeafIndex(2), 0, testUpdateProposal(t, crypto, member))); err != nil {
		t.Fatalf("a second member's first update was refused with %v; the quota is counted per sender, and one counted over the cache would refuse it",
			err)
	}
}

// TestTheWholeCacheStopsAtWhatOneValidCommitListCouldName is the other column: enough senders, each
// inside its own quota, to reach the total.
//
// The per sender quota is what a single peer spends and this is what a set of them spends together,
// and the two refusals are separate values because the remedies are: the sender quota says stop
// trusting a member, and this one says somebody has to commit.
func TestTheWholeCacheStopsAtWhatOneValidCommitListCouldName(t *testing.T) {
	crypto := testCrypto(t)
	cache := testCache(t)
	total := maxCachedProposals()
	perSender := proposalTypeCacheCeiling[ProposalTypeRemove].perSender
	stored := 0
	sender := 0
	for stored < total {
		for i := 0; i < perSender && stored < total; i += 1 {
			if _, err := cache.Store(crypto, testResolveContext(), testFloodedProposalContent(
				t, LeafIndex(sender), uint32(i), testRemoveProposal(LeafIndex(4)))); err != nil {
				t.Fatalf("Store of entry %d of %d, from leaf %d: %v; every entry under the total is one a valid commit list could name",
					stored, total, sender, err)
			}
			stored += 1
		}
		sender += 1
	}
	if held := len(cache.Pending(testResolveContext())); held != total {
		t.Fatalf("Pending answers %d at the entry ceiling, want %d", held, total)
	}
	// the last sender still has quota left, so what refuses this is the total and not the quota
	if used := cache.perSender[proposalCacheQuota{sender: LeafIndex(sender - 1), proposalType: ProposalTypeRemove}]; used >= perSender {
		t.Fatalf("leaf %d has spent %d of its %d, so this next store would be refused by the quota and the total would not be observed",
			sender-1, used, perSender)
	}
	_, err := cache.Store(crypto, testResolveContext(), testFloodedProposalContent(
		t, LeafIndex(sender-1), uint32(perSender), testRemoveProposal(LeafIndex(4))))
	if !errors.Is(err, errProposalCacheFull) {
		t.Fatalf("the entry past the total answered %v, want errProposalCacheFull", err)
	}
	if held := len(cache.Pending(testResolveContext())); held != total {
		t.Fatalf("Pending answers %d after the refusal, want %d", held, total)
	}
}

// ---------------------------------------------------------------------------
// the octets, which the entry ceiling does not bound
// ---------------------------------------------------------------------------

// TestOneEnormousProposalDoesNotSatisfyACeilingCountedInEntriesAlone is the second dimension.
//
// syntax.MaxVectorLength caps a single field at a mebibyte and a group_context_extensions proposal
// is a vector of extensions each carrying an opaque body, so one accepted entry is worth about a
// mebibyte -- and maxCachedProposals of them are worth about a gibibyte and a half. This asserts
// that what stops the run is the OCTET ceiling and that the entry count when it stops is a tiny
// fraction of the entry ceiling, because a test that only asserted "eventually refused" would pass
// over an implementation with no octet ceiling at all.
func TestOneEnormousProposalDoesNotSatisfyACeilingCountedInEntriesAlone(t *testing.T) {
	crypto := testCrypto(t)
	cache := testCache(t)
	stored := 0
	var err error
	// one per sender, because a group_context_extensions proposal is one per sender by the same
	// section 12.2 rule; the octets are what this is about and the quota must not be what fires
	for sender := 0; sender < maxCachedProposals(); sender += 1 {
		if _, err = cache.Store(crypto, testResolveContext(), testProposalContentAt(
			t, LeafIndex(sender), []byte("group"), 1, testEnormousProposal())); err != nil {
			break
		}
		stored += 1
	}
	if !errors.Is(err, errProposalCacheOctets) {
		t.Fatalf("a run of proposals worth about a mebibyte each stopped with %v after %d of them, want errProposalCacheOctets; a cache bounded only on its entry count admits maxCachedProposals of these",
			err, stored)
	}
	if stored < 2 {
		t.Fatalf("only %d of these were accepted, so the octet ceiling is refusing an honest single proposal rather than an accumulation", stored)
	}
	if stored >= maxCachedProposals() {
		t.Fatalf("%d were accepted against an entry ceiling of %d, so the entry ceiling is what stopped this and the octet one was never observed",
			stored, maxCachedProposals())
	}
	if cache.octets > maxCachedProposalOctets {
		t.Fatalf("the cache holds %d octets against a ceiling of %d; the refusal has to come before the entry lands or the ceiling is one entry wide",
			cache.octets, maxCachedProposalOctets)
	}
	// what refused the run is the SUM and not the entry offered, and both halves of that are
	// observable. The headroom left is smaller than the proposal that was refused, so the ceiling
	// is what bound; and one proposal of exactly that size into an empty cache is accepted, so the
	// ceiling is over what this cache holds for an epoch rather than over one message. A ceiling
	// written per proposal would pass the first of those and fail the second.
	if headroom := maxCachedProposalOctets - cache.octets; headroom >= syntax.MaxVectorLength {
		t.Errorf("the run stopped with %d octets of headroom under the %d ceiling, which is more than the proposal it refused; something other than the ceiling ended it",
			headroom, maxCachedProposalOctets)
	}
	if _, alone := testCache(t).Store(crypto, testResolveContext(), testProposalContentAt(
		t, LeafIndex(0), []byte("group"), 1, testEnormousProposal())); alone != nil {
		t.Fatalf("one proposal of this size into an empty cache was refused with %v; the octet ceiling is over what the cache holds for a whole epoch and not over one message",
			alone)
	}
	t.Logf("%d proposals of about a mebibyte each were accepted into an entry ceiling of %d before the %d octet ceiling refused the next",
		stored, maxCachedProposals(), maxCachedProposalOctets)
}

// ---------------------------------------------------------------------------
// what the ceilings are asked of, and what releases them
// ---------------------------------------------------------------------------

// TestACeilingIsAskedOnlyOfAnEntryTheCacheDoesNotAlreadyHold is the idempotence half.
//
// The key is a hash over the whole message, so a re-delivery is the same key and costs this cache
// nothing more. A ceiling asked of it would answer a sentence about a limit to a caller holding a
// message this cache already agreed to, and would let one duplicated message reach a quota.
func TestACeilingIsAskedOnlyOfAnEntryTheCacheDoesNotAlreadyHold(t *testing.T) {
	crypto := testCrypto(t)
	member := testIdentity(t, crypto, "bob")
	cache := testCache(t)
	content := testFloodedProposalContent(t, LeafIndex(1), 0, testUpdateProposal(t, crypto, member))
	first, err := cache.Store(crypto, testResolveContext(), content)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	octets := cache.octets
	again, err := cache.Store(crypto, testResolveContext(), content)
	if err != nil {
		t.Fatalf("the same message delivered twice was refused with %v; the second delivery is the entry the cache already holds, and the update quota is one",
			err)
	}
	if string(again) != string(first) {
		t.Fatalf("the same message answered two references, %x and %x", first, again)
	}
	if held := len(cache.Pending(testResolveContext())); held != 1 {
		t.Fatalf("Pending answers %d after one message delivered twice, want 1", held)
	}
	if cache.octets != octets {
		t.Fatalf("the octets went from %d to %d over a re-delivery; an entry counted twice is a ceiling one duplicated message can reach",
			octets, cache.octets)
	}
	// and the quota really was spent by the first, so the exemption is about identity and not
	// about the rule being off
	if _, second := cache.Store(crypto, testResolveContext(),
		testFloodedProposalContent(t, LeafIndex(1), 1, testUpdateProposal(t, crypto, member))); !errors.Is(second, errProposalCacheSenderQuota) {
		t.Fatalf("a genuinely second update answered %v, want errProposalCacheSenderQuota", second)
	}
}

// TestRebindReleasesTheOctetsAndTheSenderQuotasWithTheEntries is the boundary half.
//
// A rebind that emptied byRef and kept the arithmetic would open the new epoch with the closed
// epoch's cache already full: every sender would arrive at its quota having cached nothing in the
// epoch it is now in. That is the permanent wedge this whole file was rewritten to remove,
// reintroduced through the accounting rather than through the binding, so it is held by a test.
func TestRebindReleasesTheOctetsAndTheSenderQuotasWithTheEntries(t *testing.T) {
	crypto := testCrypto(t)
	member := testIdentity(t, crypto, "bob")
	cache := testCache(t)
	if _, err := cache.Store(crypto, testResolveContext(),
		testFloodedProposalContent(t, LeafIndex(1), 0, testUpdateProposal(t, crypto, member))); err != nil {
		t.Fatalf("Store in the first epoch: %v", err)
	}
	if cache.octets == 0 {
		t.Fatal("the cache counted no octets for an entry it holds, so the release below observes nothing")
	}
	next := testResolveContextAt([]byte("group"), 2)
	if err := cache.Rebind(next); err != nil {
		t.Fatalf("Rebind: %v", err)
	}
	if cache.octets != 0 {
		t.Errorf("the cache holds %d octets after a rebind emptied it; an octet total carried across a boundary is a cache that is full of an epoch that has closed",
			cache.octets)
	}
	if held := len(cache.perSender); held != 0 {
		t.Errorf("%d sender quotas survived the rebind; a member arriving at its quota having cached nothing in this epoch is the wedge the binding rewrite removed",
			held)
	}
	if _, err := cache.Store(crypto, next,
		testFloodedProposalContent2(t, LeafIndex(1), 0, 2, testUpdateProposal(t, crypto, member))); err != nil {
		t.Fatalf("the same member's first update of the NEW epoch was refused with %v; its quota belongs to the epoch that closed",
			err)
	}
}

// testFloodedProposalContent2 is testFloodedProposalContent with the epoch named, for the one test
// that stores either side of a boundary.
func testFloodedProposalContent2(t *testing.T, sender LeafIndex, nonce uint32, epoch uint64,
	proposal *Proposal) *AuthenticatedContent {

	t.Helper()
	content := testProposalContentAt(t, sender, []byte("group"), epoch, proposal)
	content.Content.AuthenticatedData = binary.BigEndian.AppendUint32(nil, nonce)
	return content
}

// TestAnAcceptedTypeWithNoCeilingIsRefusedRatherThanAdmittedWithoutBound performs the commit that
// makes checkCacheCeiling's first branch reachable, for the length of one test.
//
// It is the shape TestABucketlessAcceptedTypeIsRefusedRatherThanSilentlyDropped takes one rule over,
// and it exists for the same reason. Nothing this build can assemble reaches that branch today --
// every value arriving at it has been through the profile gate, and the four types the profile
// accepts are exactly the four the ceiling table has rows for. What makes it reachable is the commit
// that widens the accepted set, and a fifth accepted type admitted with no ceiling would be the one
// type this cache held without bound: counted by nothing, refused by nothing, and answered whole by
// Pending. So the branch refuses rather than defaulting, and this performs the widening so the line
// is executed rather than reasoned about.
//
// The row is removed by the cleanup whether this passes or fails, because every other test in this
// file and the next derives its class off the same table.
func TestAnAcceptedTypeWithNoCeilingIsRefusedRatherThanAdmittedWithoutBound(t *testing.T) {
	crypto := testCrypto(t)
	const widened = ProposalType(0x0C0C)
	if _, already := proposalTypeProfile[widened]; already {
		t.Fatalf("%#04x is already classified, so this test is not modelling a widening at all", uint16(widened))
	}
	if _, already := proposalTypeCacheCeiling[widened]; already {
		t.Fatalf("%#04x already has a ceiling, so the branch this test is about cannot be reached through it",
			uint16(widened))
	}
	proposalTypeProfile[widened] = nil
	t.Cleanup(func() { delete(proposalTypeProfile, widened) })

	accepted := &Proposal{ProposalType: widened, UnknownBody: []byte{0xc0, 0xff, 0xee}}
	if err := checkProposalProfile(defaultProfile(), accepted); err != nil {
		t.Fatalf("the widened profile refused %#04x with %v, so this never reaches the ceiling lookup and the branch is still unobserved",
			uint16(widened), err)
	}
	_, err := testCache(t).Store(crypto, testResolveContext(),
		testFloodedProposalContent(t, LeafIndex(1), 0, accepted))
	if !errors.Is(err, errAcceptedTypeHasNoCeiling) {
		t.Fatalf("an accepted type with no ceiling stored with err = %v, want errAcceptedTypeHasNoCeiling; a type admitted with no ceiling is the one type this cache holds without bound",
			err)
	}
	// and it is not the refusal an unsupported type gets. The two are opposite: this type IS
	// supported -- the profile was just widened to accept it -- and what is missing is a ceiling
	// on THIS side. A caller told the type was unsupported would go and look at the peer.
	if errors.Is(err, errUnregisteredProposalType) || errors.Is(err, errReservedProposalType) {
		t.Errorf("the ceilingless refusal answers to a type refusal as well: %v", err)
	}
}

