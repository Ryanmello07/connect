// The five defects batch B's review reproduced, each held by the property it escaped through
// rather than by the shape of the fix.
//
// They are in a file of their own because each is a REGRESSION case with a measurement behind it,
// and a reader asking "what stopped this" should find the measurement beside the assertion rather
// than three files away.
package messagegroup

import (
	"bytes"
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"slices"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// a zeroized ratchet is dead, and the key it would otherwise hand out
// ---------------------------------------------------------------------------

// Zeroize erased the arrays in place and left both ratchets fully operational, so the next call
// derived from thirty two zeros. Measured: two ratchets on DIFFERENT groups and DIFFERENT leaves
// both answered index 1 with key 00*32 after Zeroize, and RecordAeadBody of that constant is one
// key and one nonce every party in the world can compute. The reservation SUCCEEDED, so the index
// was durably consumed under it.
//
// The case asserts the refusal AND the shape of what the defect produced, so a fix that refused
// for some other reason -- or one that answered a different constant -- is still reported.
func TestAZeroizedSenderRatchetHandsOutNothing(t *testing.T) {
	ratchet, err := NewSenderRatchet(ratchetClassKey(), ratchetLeaf, ratchetGroup, newStreamIndexMemory())
	if err != nil {
		t.Fatalf("build the ratchet: %v", err)
	}
	index, key, err := ratchet.Next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if len(key) == 0 {
		t.Fatal("the ratchet answered no key before it was zeroized, so this case would pass over one that answers nothing at all")
	}
	zeroize(key)
	ratchet.Zeroize()
	for attempt := range 3 {
		index, key, err = ratchet.Next()
		if !errors.Is(err, ErrRatchetZeroized) {
			t.Errorf("attempt %d after Zeroize answered %v, want ErrRatchetZeroized", attempt, err)
		}
		if key != nil || index != 0 {
			t.Errorf("attempt %d after Zeroize answered index %d and a %d octet key", attempt, index, len(key))
		}
	}
	// and the index is not burned either: the refusal is BEFORE the reservation, so a call
	// after Zeroize costs the store nothing.
	reserver := newStreamIndexMemory()
	second, err := NewSenderRatchet(ratchetClassKey(), ratchetLeaf, ratchetGroup, reserver)
	if err != nil {
		t.Fatalf("build the second ratchet: %v", err)
	}
	second.Zeroize()
	if _, _, err := second.Next(); !errors.Is(err, ErrRatchetZeroized) {
		t.Fatalf("the second ratchet answered %v", err)
	}
	if high, _ := reserver.HighWater(ratchetGroup); high != 0 {
		t.Errorf("a call on a zeroized ratchet moved the store's high water to %d; the refusal is ordered before the reservation exactly so that it costs no index", high)
	}
}

func TestAZeroizedReceiverRatchetHandsOutNothing(t *testing.T) {
	ratchet, err := NewReceiverRatchet(ratchetClassKey(), ratchetLeaf, 0, 8)
	if err != nil {
		t.Fatalf("build the ratchet: %v", err)
	}
	key, err := ratchet.KeyFor(0)
	if err != nil {
		t.Fatalf("key for 0: %v", err)
	}
	// the constant the defect produced, computed here so the assertion is about the VALUE and
	// not merely about an error being returned.
	worldReadable, err := NewReceiverRatchet(make([]byte, classKeyBytes), ratchetLeaf, 0, 8)
	if err != nil {
		t.Fatalf("build the control: %v", err)
	}
	fromZeros, err := worldReadable.KeyFor(0)
	if err != nil {
		t.Fatalf("the control could not answer: %v", err)
	}
	if bytes.Equal(key, fromZeros) {
		t.Fatal("a live ratchet already answers the key a zeroized class key produces, so this case cannot tell the two apart")
	}
	zeroize(key)
	ratchet.Zeroize()
	for _, refusal := range []struct {
		name string
		call func() ([]byte, error)
	}{
		{name: "KeyFor", call: func() ([]byte, error) { return ratchet.KeyFor(1) }},
		{name: "PeekFor", call: func() ([]byte, error) { return ratchet.PeekFor(1) }},
		{name: "Commit", call: func() ([]byte, error) { return nil, ratchet.Commit(1) }},
	} {
		answer, err := refusal.call()
		if !errors.Is(err, ErrRatchetZeroized) {
			t.Errorf("%s after Zeroize answered %v, want ErrRatchetZeroized", refusal.name, err)
		}
		if answer != nil {
			t.Errorf("%s after Zeroize answered %d octets beside its error", refusal.name, len(answer))
		}
	}
}

// ---------------------------------------------------------------------------
// two retention classes of one group do not share a counter
// ---------------------------------------------------------------------------

// Measured on the shape the reserver used to declare: two ratchets over one reserver, keyed on
// the group alone, left the second answering "a stream index has already been consumed" on every
// attempt with its position stuck at 1 forever. At most one retention class per group could ever
// send, and no test in batch B constructed two sender ratchets over one reserver.
func TestTwoRetentionClassesOfOneGroupDoNotShareACounter(t *testing.T) {
	reserver := newStreamIndexMemory()
	classKeys := DeriveClassKeys(StorageRoot(keyScheduleKatInputs()))
	group := streamKeyNamed("one group")
	durableStream := group
	durableStream.RetentionWire = 0x01
	permStream := group
	permStream.RetentionWire = 0x00
	if durableStream == permStream {
		t.Fatal("the two streams are the same value, so this case cannot tell a shared counter from a separate one")
	}
	durable, err := NewSenderRatchet(classKeys.Durable, ratchetLeaf, durableStream, reserver)
	if err != nil {
		t.Fatalf("the durable ratchet: %v", err)
	}
	permanent, err := NewSenderRatchet(classKeys.Perm, ratchetLeaf, permStream, reserver)
	if err != nil {
		t.Fatalf("the permanent ratchet: %v", err)
	}
	for round := range 4 {
		durableIndex, durableKey, err := durable.Next()
		if err != nil {
			t.Fatalf("round %d, the durable ratchet: %v", round, err)
		}
		permIndex, permKey, err := permanent.Next()
		if err != nil {
			t.Fatalf("round %d, the permanent ratchet: %v", round, err)
		}
		if durableIndex != uint64(round+1) || permIndex != uint64(round+1) {
			t.Errorf("round %d answered durable %d and permanent %d; two streams count independently",
				round, durableIndex, permIndex)
		}
		if bytes.Equal(durableKey, permKey) {
			t.Errorf("round %d: the two classes answered one record key", round)
		}
		zeroize(durableKey)
		zeroize(permKey)
	}
}

// An index the store has already consumed is a PERMANENT refusal, and the ratchet stops rather
// than offering it again forever.
//
// Both directions: a transient failure leaves the ratchet offering the same index -- which is what
// makes a full disk a retry rather than a hole in the stream -- and a consumed one wedges it.
func TestAConsumedIndexWedgesTheRatchetAndATransientFailureDoesNot(t *testing.T) {
	transient := &streamIndexRefusing{err: errors.New("the disk is full")}
	retrying, err := NewSenderRatchet(ratchetClassKey(), ratchetLeaf, ratchetGroup, transient)
	if err != nil {
		t.Fatalf("build the ratchet: %v", err)
	}
	for attempt := range 3 {
		if _, _, err := retrying.Next(); errors.Is(err, ErrSenderRatchetWedged) {
			t.Fatalf("attempt %d treated a transient failure as permanent", attempt)
		}
		if retrying.Position() != 1 {
			t.Errorf("attempt %d moved the position to %d; a refused reservation offers the same index to the next call", attempt, retrying.Position())
		}
	}

	consumed := &streamIndexRefusing{err: ErrStreamIndexConsumed}
	wedged, err := NewSenderRatchet(ratchetClassKey(), ratchetLeaf, ratchetGroup, consumed)
	if err != nil {
		t.Fatalf("build the ratchet: %v", err)
	}
	for attempt := range 3 {
		index, key, err := wedged.Next()
		if !errors.Is(err, ErrSenderRatchetWedged) {
			t.Errorf("attempt %d over a consumed index answered %v, want ErrSenderRatchetWedged", attempt, err)
		}
		if key != nil || index != 0 {
			t.Errorf("attempt %d answered index %d and a %d octet key", attempt, index, len(key))
		}
	}
	if consumed.reserves != 1 {
		t.Errorf("the wedged ratchet reserved %d times; the point of wedging is that it stops asking for an index that will never be free", consumed.reserves)
	}
}

// ---------------------------------------------------------------------------
// both ladder walks are bounded
// ---------------------------------------------------------------------------

// Measured at roughly four hundred nanoseconds a rung: a head of 2^32 is about half an hour of one
// core and 2^63 never returns. Neither number is authenticated at the moment it is read -- a
// receiver's head is a position in a peer's stream and a sender's resume is whatever a store hands
// back -- so an unbounded walk is a denial with no ceiling.
func TestNeitherLadderResumeWalksWithoutABound(t *testing.T) {
	if _, err := NewReceiverRatchet(ratchetClassKey(), ratchetLeaf, uint64(maxLadderWalk)+1, 8); !errors.Is(err, ErrLadderWalkTooLong) {
		t.Errorf("a receiver at one past the bound answered %v, want ErrLadderWalkTooLong", err)
	}
	if _, err := NewReceiverRatchet(ratchetClassKey(), ratchetLeaf, ^uint64(0), 8); !errors.Is(err, ErrLadderWalkTooLong) {
		t.Errorf("a receiver at the largest index a u64 holds answered %v, want ErrLadderWalkTooLong", err)
	}
	// and the bound is not zero: a resume AT it is answered, so the refusal is a ceiling rather
	// than a ban.
	if _, err := NewReceiverRatchet(ratchetClassKey(), ratchetLeaf, 4, 8); err != nil {
		t.Errorf("a receiver four rungs along was refused: %v", err)
	}

	resuming := newStreamIndexMemory()
	resuming.image[streamIndexRowKey(ratchetGroup)] = uint64(maxLadderWalk) + 1
	if _, err := NewSenderRatchet(ratchetClassKey(), ratchetLeaf, ratchetGroup, resuming); !errors.Is(err, ErrLadderWalkTooLong) {
		t.Errorf("a sender resuming past the bound answered %v, want ErrLadderWalkTooLong", err)
	}
	short := newStreamIndexMemory()
	short.image[streamIndexRowKey(ratchetGroup)] = 4
	if _, err := NewSenderRatchet(ratchetClassKey(), ratchetLeaf, ratchetGroup, short); err != nil {
		t.Errorf("a sender resuming four rungs along was refused: %v", err)
	}
}

// ---------------------------------------------------------------------------
// the eviction policy, stated as the property that is true
// ---------------------------------------------------------------------------

// The claim used to be "a member holding a handful of skipped keys never pays for a member holding
// a thousand", and it is FALSE: evicting from the fullest EQUALISES, so once the bound is exceeded
// every holder above bound/senders loses rungs. Measured at the shipped defaults, where the table
// bound and one window are the same number: three honest senders, two holding four hundred skipped
// rungs each and a third taking a full window reorder, left the two at 341.
//
// The property that IS true is the fair share, and it takes THREE senders to state: a member
// holding fewer than retainedBound/senders never loses a rung at all. Batch B's own case used two
// senders with a bound of 12 and a window of 64, where bound/n = 6 exceeded the quiet member's
// holding of 2 and the property was unfalsifiable.
func TestAMemberBelowItsFairShareNeverLosesARungToAnotherMembersFlood(t *testing.T) {
	const bound = 90
	const window = 64
	table, err := NewReceiverRatchets(bound)
	if err != nil {
		t.Fatalf("build the table: %v", err)
	}
	classKey := ratchetClassKey()
	keys := []ReceiverRatchetKey{}
	for i := range 3 {
		key := ReceiverRatchetKey{RetentionWire: 0x01}
		key.SenderHandle[0] = byte(i + 1)
		ratchet, err := NewReceiverRatchet(classKey, uint32(i), 0, window)
		if err != nil {
			t.Fatalf("build ratchet %d: %v", i, err)
		}
		table.Track(key, ratchet)
		keys = append(keys, key)
	}
	// the fair share, DERIVED from the bound and the number of senders rather than written down.
	fairShare := bound / len(keys)
	quiet := fairShare - 2
	if quiet <= 0 {
		t.Fatalf("the fair share is %d, so there is no holding below it and this case cannot fail", fairShare)
	}
	// two quiet members, each holding fewer than its share, and one flooder taking a full window.
	for _, key := range keys[:2] {
		if _, err := table.KeyFor(key, uint64(quiet)); err != nil {
			t.Fatalf("the quiet member could not skip: %v", err)
		}
	}
	held := map[ReceiverRatchetKey][]uint64{}
	for _, key := range keys[:2] {
		for index := range uint64(quiet) {
			held[key] = append(held[key], index)
		}
	}
	if _, err := table.KeyFor(keys[2], uint64(window)); err != nil {
		t.Fatalf("the flooding member could not skip a full window: %v", err)
	}
	if table.Retained() > bound {
		t.Fatalf("the table holds %d retained rungs and the bound is %d", table.Retained(), bound)
	}
	for i, key := range keys[:2] {
		for _, index := range held[key] {
			answer, err := table.KeyFor(key, index)
			if err != nil {
				t.Errorf("quiet member %d held %d rungs, fewer than its fair share of %d, and lost index %d to another member's flood: %v",
					i, quiet, fairShare, index, err)
				break
			}
			zeroize(answer)
		}
	}
}

// The tie between two equally full windows is broken by the order they were TRACKED in, and Track
// is what stamps that order.
//
// Both mutations batch B's review found surviving are refused here: inverting the comparison, and
// deleting the stamp so the victim is decided by go's randomised map iteration. The second is what
// makes this a case rather than a comment -- a tie broken by iteration order passes on most runs.
func TestTheEvictionTieIsBrokenByTheOrderTheRatchetsWereTracked(t *testing.T) {
	const bound = 7
	const window = 16
	table, err := NewReceiverRatchets(bound)
	if err != nil {
		t.Fatalf("build the table: %v", err)
	}
	classKey := ratchetClassKey()
	first := ReceiverRatchetKey{RetentionWire: 0x01}
	first.SenderHandle[0] = 0xA1
	second := ReceiverRatchetKey{RetentionWire: 0x01}
	second.SenderHandle[0] = 0xB2
	for _, key := range []ReceiverRatchetKey{first, second} {
		ratchet, err := NewReceiverRatchet(classKey, 1, 0, window)
		if err != nil {
			t.Fatalf("build a ratchet: %v", err)
		}
		table.Track(key, ratchet)
	}
	// each holds four skipped rungs, which is a tie the bound of seven forces a decision about.
	for _, key := range []ReceiverRatchetKey{first, second} {
		answer, err := table.KeyFor(key, 4)
		if err != nil {
			t.Fatalf("skip to 4: %v", err)
		}
		zeroize(answer)
	}
	if table.Retained() != bound {
		t.Fatalf("the table holds %d retained rungs, want exactly the bound of %d so that one eviction has happened and no more", table.Retained(), bound)
	}
	held := func(key ReceiverRatchetKey) int {
		table.tableLock.Lock()
		defer table.tableLock.Unlock()
		return table.ratchets[key].Retained()
	}
	// the EARLIER tracked of two equally full windows is the one that gives up a rung. It is an
	// order somebody stated, not an order the runtime chose.
	if held(first) != 3 || held(second) != 4 {
		t.Errorf("the earlier tracked ratchet holds %d and the later holds %d; the tie is broken by the tracking order, and a table that decided it by map iteration would answer differently between runs",
			held(first), held(second))
	}
	// and the stamps are distinct and ascending, which is what Track owes.
	table.tableLock.Lock()
	firstStamp, secondStamp := table.ratchets[first].tracked, table.ratchets[second].tracked
	table.tableLock.Unlock()
	if firstStamp == 0 || secondStamp == 0 || firstStamp >= secondStamp {
		t.Errorf("the tracking stamps are %d and %d; without an ascending stamp per ratchet the tie is decided by go's randomised map iteration, which is exactly what the stamp exists to remove",
			firstStamp, secondStamp)
	}
}

// ---------------------------------------------------------------------------
// the two erasures that were in uncovered branches
// ---------------------------------------------------------------------------

// eraseLocked's header names both erasures that are NOT it, and one of them -- the duplicate index
// arm of retainIntoWindowLocked -- is reachable only by calling the helper twice at one index. It
// is a defect in this ratchet rather than a state a peer can cause, so nothing through the public
// surface gets there, and deleting the branch survived the whole suite.
func TestRetainingOneIndexTwiceErasesTheWholeWindow(t *testing.T) {
	ratchet, err := NewReceiverRatchet(ratchetClassKey(), ratchetLeaf, 0, 8)
	if err != nil {
		t.Fatalf("build the ratchet: %v", err)
	}
	ratchet.stateLock.Lock()
	defer ratchet.stateLock.Unlock()
	first := bytes.Repeat([]byte{0x11}, 32)
	other := bytes.Repeat([]byte{0x22}, 32)
	ratchet.retainLocked(1, first)
	ratchet.retainLocked(2, other)
	if len(ratchet.window) != 2 {
		t.Fatalf("the window holds %d rungs, want 2", len(ratchet.window))
	}
	ratchet.retainLocked(1, bytes.Repeat([]byte{0x33}, 32))
	if len(ratchet.window) != 1 {
		t.Errorf("the window holds %d rungs after one index was retained twice; what it held is no longer a set of rungs this ratchet can account for, so all of it goes",
			len(ratchet.window))
	}
	for _, dropped := range [][]byte{first, other} {
		for _, octet := range dropped {
			if octet != 0 {
				t.Errorf("a dropped rung was not erased: %x", dropped)
				break
			}
		}
	}
}

// KeyFor's exhausted arm erases the chain array, and it is reachable only by parking a ratchet at
// the last index a u64 holds -- which the walk bound makes unreachable through the constructor, by
// design. The field is set directly here because that is the only way in, and the alternative is
// an erase in production source that nothing holds.
func TestTheLastRungOfTheLadderErasesTheChainArray(t *testing.T) {
	ratchet, err := NewReceiverRatchet(ratchetClassKey(), ratchetLeaf, 0, 8)
	if err != nil {
		t.Fatalf("build the ratchet: %v", err)
	}
	ratchet.stateLock.Lock()
	ratchet.head = ^uint64(0)
	chain := ratchet.secret
	ratchet.stateLock.Unlock()
	if len(chain) == 0 {
		t.Fatal("the ratchet holds no chain array, so this case would pass over one that holds nothing")
	}
	answer, err := ratchet.KeyFor(^uint64(0))
	if err != nil {
		t.Fatalf("the last index answered %v", err)
	}
	if len(answer) == 0 {
		t.Fatal("the last index answered no key")
	}
	zeroize(answer)
	for _, octet := range chain {
		if octet != 0 {
			t.Errorf("the chain array was not erased at the end of the ladder: %x", chain)
			break
		}
	}
	// and the same index is now BELOW the head rather than at it, so a second request is refused
	// rather than answered from a chain array that is all zeros.
	if _, err := ratchet.KeyFor(^uint64(0)); !errors.Is(err, ErrOutOfWindow) {
		t.Errorf("a second request for the last index answered %v, want ErrOutOfWindow", err)
	}
}

// ---------------------------------------------------------------------------
// the reserver gate reads assignability rather than method declarations
// ---------------------------------------------------------------------------

// Batch B's review probed the gate that keeps a durable reserver out of this package and found it
// derives its class from METHOD DECLARATIONS: a production type satisfying StreamIndexReserver by
// EMBEDDING it -- a decorator, a cache, a nop reserver -- is invisible to that reading, and the
// probe survived the whole suite.
//
// THIS ASKS GO/TYPES INSTEAD OF READING SHAPES, and that is the repair rather than a third shape
// added to a list of two. A gate that read "declares the methods" and then also read "embeds the
// interface" would be two enumerated shapes with a third waiting -- a named type whose underlying
// type is a function... a struct embedding a struct that embeds the interface... a defined type
// over a pointer to one. Assignability is the property; every shape is a way of having it, and
// types.Implements answers the property.
//
// The scope question (R3a), answered separately from the class question: the SCOPE is this
// package's production files, type checked as the package they are, because a durable reserver
// arriving here is what section 8.2's assignment to sdk forbids and a type in another package is
// that package's own question. The CLASS is every package level named type the checker reports,
// which is total by construction -- the reading IS the class -- and it fatals if the checker
// reports none.
func TestNoProductionTypeOfThisPackageSatisfiesTheReserver(t *testing.T) {
	fileSet := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read this package's directory: %v", err)
	}
	files := []*ast.File{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, parsed)
	}
	if len(files) == 0 {
		t.Fatal("no production file was read, so this gate type checked nothing")
	}
	config := types.Config{Importer: importer.ForCompiler(fileSet, "source", nil)}
	checked, err := config.Check("github.com/urnetwork/connect/messagegroup", fileSet, files, nil)
	if err != nil {
		t.Fatalf("type check this package's production source: %v", err)
	}
	reserverObject := checked.Scope().Lookup("StreamIndexReserver")
	if reserverObject == nil {
		t.Fatal("this package declares no StreamIndexReserver, so this gate is holding nothing")
	}
	reserver, isInterface := reserverObject.Type().Underlying().(*types.Interface)
	if !isInterface {
		t.Fatal("StreamIndexReserver is not an interface")
	}
	if reserver.NumMethods() == 0 {
		t.Fatal("StreamIndexReserver declares no method, so every type in this package satisfies it and this gate would report the whole package")
	}
	judged, satisfying := 0, []string{}
	for _, name := range checked.Scope().Names() {
		named, isNamed := checked.Scope().Lookup(name).(*types.TypeName)
		if !isNamed {
			continue
		}
		judged += 1
		subject := named.Type()
		if types.Implements(subject, reserver) || types.Implements(types.NewPointer(subject), reserver) {
			satisfying = append(satisfying, name)
		}
	}
	if judged == 0 {
		t.Fatal("the checker reported no named type in this package, so this gate examined nothing")
	}
	for _, name := range satisfying {
		if name == "StreamIndexReserver" {
			continue
		}
		t.Errorf("%s satisfies StreamIndexReserver in production source; section 8.2 assigns the durable store to sdk's MessageStore, and section 5.6's argument rests on neither half of the record layer implementing one",
			name)
	}
	// and the reading is not vacuous: the interface satisfies itself, which is the one member
	// this class must always have.
	if !slices.Contains(satisfying, "StreamIndexReserver") {
		t.Errorf("types.Implements does not read StreamIndexReserver as satisfying itself, so whatever it is comparing is not the interface and every negative above is a negative about nothing")
	}
	t.Logf("%d named type(s) type checked, %d satisfying the reserver: %v", judged, len(satisfying), satisfying)
}
