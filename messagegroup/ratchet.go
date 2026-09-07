// The two ratchets of spec A section 5.5: the sender's forward ladder over record_key[i], and
// the receiver's bounded window of the rungs it has skipped.
//
// Section 5.5 is short, and every sentence of it is load bearing:
//
//	a real forward ratchet: the sender overwrites record_key[i] after use. receivers keep a
//	bounded window of skipped keys for out-of-order receipt.
//	Next() advances and zeroes.
//	Window size: 1024 keys per (sender_handle, retention class) [...] capped at 64 senders
//	tracked per group before the oldest is evicted.
//	Beyond the window, a record is undecryptable and surfaces as a gap entry with
//	GapReason == "out_of_window" -- NOT as an error.
//
// THE LADDER POSITION IS THE STREAM INDEX, and that pin is the most consequential decision in
// this file. Nothing rules it: ledger item 143 files it as "the device wrap still owes a
// normative stream_index-to-ratchet-position mapping" and proposes exactly this repair, and it
// is taken here rather than left open because the alternative is unsafe and the unsafety is
// invisible.
//
// The reasoning, because a later reader will be tempted to undo it for the cost it carries. The
// record nonce is expanded from the record key, so key and nonce uniqueness IS uniqueness of the
// ladder position. If the position were the ratchet's own in-memory counter it would restart at
// zero on every process start, while the stream index -- which is durable -- carried on; every
// rung of the ladder would then be issued twice under one class key, and a repeated (key, nonce)
// pair under XChaCha20-Poly1305 hands out the Poly1305 one time key. connect/mls shipped that
// exact defect once, in a restored member restarting its sender ratchet at generation 0, guarded
// only by a 32 bit reuse_guard. The only state this layer can recover after a restart is the
// reserver's high water, so the position has to BE that number.
//
// The price, stated because it is real and because no document carries it. Resuming at index n
// costs n HKDF-Expand calls, and a class key is per EPOCH, so the walk is paid again at every
// commit and grows for the life of the group. Section 5.6's interface has no field a client
// could persist a ladder position in, which is what would make the walk unnecessary -- the same
// interface open item M1-5 is already about. It is filed rather than worked around: a bound
// invented here would be policy this file has no standing to make, and a lazy walk moves the
// cost to the first send rather than removing it.
//
// WHAT THIS PACKAGE'S WINDOW DOES NOT HAVE, and connect/mls's does. mls's peekFor lets a
// too-far-ahead generation MOVE the head, and ledger 2026-09-04 argues that is safe there
// because the generation only reaches peekFor after an AEAD open under sender_data_secret --
// the number has been authenticated before the window sees it. THIS LAYER HAS NO SUCH GATE:
// stream_index arrives in the record's CLEARTEXT header, so anything that can write to the
// network chooses it. So the head does not move on a refusal here, the forward walk is bounded
// by the window size on every call, and the retained keys are bounded across the WHOLE table
// rather than per ratchet. Copy the window and the eviction from mls; do not copy the catch-up.
//
// The bounds are constructor parameters and not constants. Section 14 open item 7 -- open item
// M1-12 here -- has to finalise the memory budget and it BLOCKS the A6 freeze, so a window baked
// in as a const would make that finalisation a signature change. The defaults are connect/mls's
// own two numbers, read off that package rather than restated, because M1-12's labelled
// recommendation is to adopt its shape: a TREE WIDE retained bound, so adding senders adds no
// memory at all, and eviction from the FULLEST window, so a member holding a handful of skipped
// keys never pays for a member holding a thousand. Section 5.5's "evict the oldest sender"
// starves whoever went quiet, which is the member most likely to need the window.
package messagegroup

import (
	"fmt"
	"sync"

	"github.com/urnetwork/connect/mls"
)

// The default bounds on a receiver's retained keys, taken from connect/mls rather than written
// down a second time.
//
// DefaultRecordWindowSize bounds ONE ratchet and DefaultRetainedRecordKeys bounds the whole
// table. The second is the first and not a multiple of it, which is the property that makes the
// bound independent of how many senders a group has: mls's own comment gives the argument, and
// the eviction below always lands on the fullest window so the cost falls on whoever created it.
//
// Both are read off mls's exported constants so the two packages cannot drift, and both are
// DEFAULTS rather than the values: the constructors take the numbers, because open item M1-12
// has not finalised them and a constant would make the finalisation a signature change.
const (
	DefaultRecordWindowSize   = mls.RatchetWindowSize
	DefaultRetainedRecordKeys = mls.MaxRetainedWindowKeys
)

// SenderRatchet is one sender's ladder over record_key[i] for one retention class, with the
// durable index reservation ordered in front of every key it hands out.
//
// stateLock guards recordKey, position and exhausted. reserver and groupId are written once by
// the constructor and read without it, which is what lets Next hold the lock over the whole
// reserve-then-advance sequence: two concurrent calls that interleaved between the reservation
// and the advance would hand one index to both.
//
// THE SIGNATURE IS THE THREE VALUED FORM AND THAT IS PROVISIONAL. Section 5.5 declares
// Next() (index uint64, recordKey []byte) with no error; section 5.6 requires Reserve to
// complete DURABLY before the key is produced and says SealRecord "refuses to proceed on error".
// A no-error Next cannot report a failed fsync, so either the reservation happens outside the
// ratchet -- and the ordering guarantee is back to being a convention, which section 5.2 says
// this layer must not do -- or Next panics on a disk error. Neither is written down; that is
// open item M1-13. The three valued form is taken because it is the one that can be narrowed
// later without losing information.
type SenderRatchet struct {
	stateLock sync.Mutex
	reserver  StreamIndexReserver
	groupId   []byte
	// record_key[position], this ratchet's own copy, erased by the Next that passes it on.
	recordKey []byte
	// the stream index the next call will reserve, and the ladder position that goes with it.
	position uint64
	// set when position reached the last index a u64 holds, so it cannot wrap to zero.
	exhausted bool
}

// NewSenderRatchet builds a sender's ladder for one class key and one leaf, resumed from the
// reserver's durable high water.
//
// The reserver is taken by the constructor and refused if nil, which is section 5.6's own
// instruction -- "the constructor takes the sink to make it explicit". A ratchet without one is
// a ratchet that cannot make the ordering it exists to make.
//
// The resume is HighWater() + 1 and is never a recomputed value. A ratchet that recomputed its
// position from its own state would restart at zero after a crash, which is the reuse the file
// comment above is about; a ratchet that resumed AT the high water would re-issue the last index
// the store handed out, which is the same defect one rung shallower.
//
// The walk is the cost the file comment prices. It advances the ladder once per index below the
// resume point, erasing each rung as it passes, so the ratchet holds record_key[position] and
// nothing below it when the constructor returns.
func NewSenderRatchet(classKey []byte, leaf uint32, groupId []byte, reserver StreamIndexReserver) (*SenderRatchet, error) {
	if reserver == nil {
		return nil, fmt.Errorf("%w: a sender ratchet reserves before it derives", ErrNilStreamIndexReserver)
	}
	highWater, err := reserver.HighWater(groupId)
	if err != nil {
		return nil, fmt.Errorf("messagegroup: a sender ratchet could not read its stream index high water: %w", err)
	}
	if highWater == ^uint64(0) {
		return nil, fmt.Errorf("%w: the high water is already %d", ErrSenderRatchetExhausted, highWater)
	}
	position := highWater + 1
	recordKey := RecordKeyZero(classKey, leaf)
	for walked := uint64(0); walked < position; walked += 1 {
		recordKey = stepRecordKey(recordKey)
	}
	return &SenderRatchet{
		reserver: reserver,
		// a copy, because the caller's slice is its own: a group id that moved under this
		// ratchet would reserve indices against one store row and use them against another.
		groupId:   append([]byte(nil), groupId...),
		recordKey: recordKey,
		position:  position,
	}, nil
}

// Next reserves the next stream index durably, then hands out the rung of the ladder that goes
// with it and advances past it.
//
// THE ORDER IS THE PROPERTY. The reservation is made first, its error is checked first, and the
// function returns on a non-nil error before anything of the key schedule is reached. A body
// that called Reserve and carried on regardless is reachability-identical to this one and is a
// nonce reuse machine, which is why ratchet_test.go asserts the order off the syntax tree as
// well as through an injected failing reserver.
//
// What is handed out is a COPY, and the ratchet's own array is erased in place. Section 5.5 asks
// for exactly that -- "Next() overwrites the previous key with zeros before returning" -- and
// gives the reason: the common case, a key still sitting in a live struct field, is entirely
// preventable. The caller owns what it is given and owes it the same erasure after use.
//
// The noinline directive is this package's erase helper class, reached through the hand-off: the
// ratchet's recordKey outlives this call and zeroize is where the stores are.
//
//go:noinline
func (self *SenderRatchet) Next() (uint64, []byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.exhausted {
		return 0, nil, fmt.Errorf("%w: index %d was the last", ErrSenderRatchetExhausted, self.position)
	}
	index := self.position
	if err := self.reserver.Reserve(self.groupId, index); err != nil {
		// no index and no key leave this function on a failed reservation, and the ratchet
		// does not move: the same index is offered to the next call, which is what makes a
		// full disk a retry rather than a hole in the stream.
		return 0, nil, fmt.Errorf("messagegroup: a sender ratchet could not reserve stream index %d: %w", index, err)
	}
	handed := append([]byte(nil), self.recordKey...)
	self.recordKey = stepRecordKey(self.recordKey)
	if index == ^uint64(0) {
		// the counter does not wrap. A wrap is not a wasted message: it re-issues every
		// record key and every nonce this sender has used under a class key that has not
		// moved, and both of the record's aeads fall to it.
		self.exhausted = true
	} else {
		self.position = index + 1
	}
	return index, handed, nil
}

// Position is the stream index this ratchet will reserve next, for a caller that has to report
// where a sender is without consuming an index to find out.
func (self *SenderRatchet) Position() uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.position
}

// Zeroize erases the rung this ratchet is holding.
//
// It is owed for the reason ClassKeys.Zeroize is: a session drops its ratchets at a commit, and
// the octets it drops are what forward secrecy is about.
//
//go:noinline
func (self *SenderRatchet) Zeroize() {
	if self == nil {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	zeroize(self.recordKey)
}

// ReceiverRatchet is one sender's ladder as a receiver walks it, with the rungs it has skipped
// retained in a bounded window.
//
// stateLock guards secret, head, exhausted and window. windowSize is written once by the
// constructor.
//
// WHAT IT IS KEYED BY is not stated by any document. Section 5.5's prose scopes the window to
// (sender_handle, retention class); the constructor here is keyed by (class key, leaf index)
// because that is what record_key[0] binds, and sender_handle and leaf_index are different
// identifiers with different lifetimes -- section 5.3 makes the handle deliberately epoch stable
// and a leaf index is not. Which one keys the table decides whether a member's stream survives an
// epoch change. That is open item M1-11, and ReceiverRatchets below tracks by the handle and the
// retention wire byte because those are what a record carries, while a ratchet is BUILT from the
// leaf because that is what the derivation takes.
type ReceiverRatchet struct {
	stateLock sync.Mutex
	// record_key[head], the next rung this ratchet has not yet produced.
	secret []byte
	head   uint64
	// set when head reached the last index a u64 holds, so "below the head" can still
	// classify it.
	exhausted bool
	// the skipped rungs, by index. nil until the first skip, so an in-order receipt
	// allocates no window at all.
	window     map[uint64][]byte
	windowSize int
	// the order this ratchet was tracked in, which is how the table below breaks a tie
	// between two equally full windows. It is a counter and not a comparison of the two
	// senders octets: guardrail G8 sends every comparison of octets in this tree through
	// subtle.ConstantTimeCompare, an ORDERING cannot be spelled that way, and a handle is
	// public but the rule is derived over the whole tree rather than argued case by case.
	tracked uint64
}

// NewReceiverRatchet builds a receiver's view of one sender's ladder, positioned at headIndex.
//
// headIndex is the ladder position -- and so the stream index, per the pin the file comment
// argues -- of the first rung this ratchet will produce. It is a parameter and not zero because
// a receiver that first hears from a sender part way along its stream has to be able to say so:
// with the window bounded, a ratchet parked at zero can never reach a sender already past the
// window, and no document names who supplies the number. The walk to headIndex costs one
// expansion per index, which is the same price the sender pays to resume.
//
// windowSize bounds BOTH the retained skipped rungs of this ratchet and the forward walk one
// call may make, and the second is what makes an unauthenticated index safe to read: the stream
// index arrives in the record's cleartext header, so a peer that picks one out of the air can
// cost this receiver at most windowSize expansions and windowSize retained keys before it is
// refused.
func NewReceiverRatchet(classKey []byte, leaf uint32, headIndex uint64, windowSize int) (*ReceiverRatchet, error) {
	if windowSize <= 0 {
		return nil, fmt.Errorf("%w: window size %d", ErrWindowSize, windowSize)
	}
	secret := RecordKeyZero(classKey, leaf)
	for walked := uint64(0); walked < headIndex; walked += 1 {
		secret = stepRecordKey(secret)
	}
	return &ReceiverRatchet{
		secret:     secret,
		head:       headIndex,
		windowSize: windowSize,
	}, nil
}

// KeyFor answers the record key for one stream index, filling and pruning the window on the way.
//
// The three cases and the order they are decided in. A retained rung is handed over and dropped
// from the window, so a second request for it is refused: a window that hands the same key out
// twice is a window that survives a replay. An index the head has already passed is refused,
// because this ratchet no longer holds it and cannot re-derive it -- that is the forward secrecy
// of the ladder, not a lookup failure. An index further ahead than the window is refused AND THE
// HEAD DOES NOT MOVE, which is where this ratchet parts company with connect/mls's peekFor: the
// argument that lets mls advance on a refusal is that the generation was authenticated before the
// window saw it, and nothing authenticates a stream index at this layer.
//
// Both refusals are ErrOutOfWindow, and the conflation is deliberate but is not free. A rung
// erased because it was answered and a rung evicted because the window filled are the same state
// here -- an index below the head that is not retained -- and telling them apart needs a
// tombstone per index. Section 5.5 asks for one visible outcome, a gap, and both of these are
// one; what a caller CANNOT do with this error is tell a replay from a loss, and open item M1-15
// is where that has to be settled if sdk needs to.
//
// The common case allocates nothing: an index equal to the head takes one step and never touches
// the window, which is section 5.5's first requirement of this function.
//
// The noinline directive is carried by the convention connect/mls's peekFor states rather than
// because the class zeroize_test.go derives holds this function: the prune at the end erases
// through storage that outlives the call, and the directive is what keeps those stores across a
// boundary the compiler cannot see through. The derived class follows a hand-off by ARGUMENT and
// this erasure is reached through a method call on the receiver, which is the line mls draws and
// the reason it draws it.
//
//go:noinline
func (self *ReceiverRatchet) KeyFor(index uint64) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if retained, isRetained := self.window[index]; isRetained {
		// the caller owns it from here, so it is dropped rather than erased: erasing it
		// would hand back thirty two zeros, which is a key every party in the world can
		// compute. It is this ratchet own copy and never the chain array, so nothing the
		// ratchet still holds is handed away with it.
		delete(self.window, index)
		return retained, nil
	}
	if index < self.head || (self.exhausted && index == self.head) {
		return nil, fmt.Errorf("%w: index %d is below this receiver's head %d", ErrOutOfWindow, index, self.head)
	}
	if uint64(self.windowSize) < index-self.head {
		return nil, fmt.Errorf("%w: index %d is %d ahead of head %d, and the window is %d",
			ErrOutOfWindow, index, index-self.head, self.head, self.windowSize)
	}
	// Every rung leaves this ratchet as a COPY and the chain array is erased as the ladder
	// passes it, which is the sender discipline applied on this side too. Without the copy the
	// window and the caller would hold the very array the next step erases, so the erasure
	// would have to be dropped -- and a ladder that never erases the rung it has passed is a
	// ladder an attacker who takes the process reads backwards to the epoch start.
	for self.head < index {
		self.retainLocked(self.head, append([]byte(nil), self.secret...))
		self.secret = stepRecordKey(self.secret)
		self.head += 1
	}
	handed := append([]byte(nil), self.secret...)
	if self.head == ^uint64(0) {
		// there is no successor, and the head stays where it is so that a later request for
		// this index is classified as consumed rather than as future. The chain array is
		// erased anyway: there is nothing left to derive from it.
		self.exhausted = true
		zeroize(self.secret)
	} else {
		self.secret = stepRecordKey(self.secret)
		self.head += 1
	}
	self.pruneLocked()
	return handed, nil
}

// Retained is how many skipped rungs this ratchet is holding, which is what the table's global
// bound is computed over.
func (self *ReceiverRatchet) Retained() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.window)
}

// Zeroize erases the rung this ratchet is parked on and every rung in its window.
//
// The window is walked here rather than handed to eraseLocked one index at a time, and the
// reason is a gate rather than a preference: connect/mls reads erasure FIELD BY FIELD off the
// source, and an erase that reaches a field only through a helper taking an index is an erase
// that reading cannot follow. eraseLocked stays the single site for one entry leaving the window
// while the ratchet is running -- answered, evicted -- and this is the whole map going at once.
//
//go:noinline
func (self *ReceiverRatchet) Zeroize() {
	if self == nil {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	zeroize(self.secret)
	for index, secret := range self.window {
		zeroize(secret)
		delete(self.window, index)
	}
}

// retainLocked puts one skipped rung in the window, allocating the window on first use.
//
// The window is allocated lazily, so an in-order receipt -- which retains nothing -- never builds
// one at all: section 5.5 first requirement of KeyFor is that the common case costs one step and
// no window.
//
// The odd looking shape of that guard is deliberate and is a gate rather than a preference. The
// assignment that allocates the window REPLACES whatever the field held, and connect/mls reads
// every write to a field holding key material as a drop site -- satisfied by a refusal that
// LEAVES when there is something to drop, which is this != nil arm, and NOT by the == nil
// presence guard that reads the same way to a person. That distinction was measured over there:
// a production holder dropping a live value behind a presence guard left the whole gate green.
//
// The caller holds stateLock.
//
//go:noinline
func (self *ReceiverRatchet) retainLocked(index uint64, secret []byte) {
	if self.window != nil {
		self.retainIntoWindowLocked(index, secret)
		return
	}
	self.window = map[uint64][]byte{}
	self.retainIntoWindowLocked(index, secret)
}

// retainIntoWindowLocked stores one rung in a window that already exists, erasing anything at
// that index rather than dropping it.
//
// The caller holds stateLock.
//
//go:noinline
func (self *ReceiverRatchet) retainIntoWindowLocked(index uint64, secret []byte) {
	if _, wasRetained := self.window[index]; wasRetained {
		// Reaching this at all means the ladder produced one index twice, which is a defect in
		// this ratchet and not a state a peer can cause. The whole window goes rather than the
		// one entry: what is held is no longer a set of rungs this ratchet can account for, and
		// erasing all of it is both the safe answer and the one connect/mls read off the
		// source, which follows an erase through the FIELD and not through a helper taking an
		// index.
		for existing, dropped := range self.window {
			zeroize(dropped)
			delete(self.window, existing)
		}
	}
	self.window[index] = secret
}

// eraseLocked zeroizes one retained rung and drops it.
//
// It is the one erase site for a rung leaving the window WHILE THE RATCHET IS RUNNING:
// evictOldestLocked chooses which rung goes and then comes here, so the two ways an entry is
// dropped for room cannot have the erasure on one path and not the other. A bare delete leaves
// live record keys wherever the allocator puts them next and nothing this ratchet still reaches
// can see the difference, which is a shape connect/mls has already measured passing every test it
// had.
//
// The two erasures that are NOT here, named rather than left for a reader to find contradicting
// the sentence above. Zeroize walks the whole map itself, because connect/mls reads erasure FIELD
// BY FIELD off the source and cannot follow an erase that reaches a field only through a helper
// taking an index. retainIntoWindowLocked erases what it would overwrite, for the same reading.
// Both are the whole map or one entry going for a reason this one does not cover, and both are
// held by the same test.
//
// Total by design: erasing an index that was never retained is a no-op.
//
// The caller holds stateLock.
//
//go:noinline
func (self *ReceiverRatchet) eraseLocked(index uint64) {
	secret, isRetained := self.window[index]
	if !isRetained {
		return
	}
	zeroize(secret)
	delete(self.window, index)
}

// evictOldestLocked drops the oldest retained rung, erasing it in place.
//
// The oldest is what goes, because a skipped index that has not arrived yet grows less likely to
// arrive the older it gets.
//
// The caller holds stateLock. The noinline directive is the same convention KeyFor's is: the
// erasure is eraseLocked's, reached through a method call on this receiver.
//
//go:noinline
func (self *ReceiverRatchet) evictOldestLocked() {
	if len(self.window) == 0 {
		return
	}
	oldest := ^uint64(0)
	for index := range self.window {
		if index < oldest {
			oldest = index
		}
	}
	self.eraseLocked(oldest)
}

// pruneLocked holds THIS ratchet to its own window size.
//
// It is a bound on memory and the party who decides how much of it gets used is whoever writes
// the stream indices. ReceiverRatchets.pruneRetainedLocked is the other half, and it is the half
// that matters when the number of ratchets is not this receiver's choice.
//
// The caller holds stateLock.
func (self *ReceiverRatchet) pruneLocked() {
	for self.windowSize < len(self.window) {
		self.evictOldestLocked()
	}
}

// ReceiverRatchetKey is what one receiver ratchet is tracked under: the handle the server routes
// on and the retention class wire byte the record carries.
//
// The retention byte and not the parsed class, because section 5.1 encodes the class and the eph
// bucket in ONE octet -- 0x10 given a bucket, for the eph classes -- and a table keyed on the
// parsed class alone would put two eph buckets on one ladder. It is the wire byte for a second
// reason too: connect/message declares the parsed type, and this package does not put a
// production call across that boundary until task 11.
type ReceiverRatchetKey struct {
	SenderHandle  [16]byte
	RetentionWire byte
}

// ReceiverRatchets is the table of one group's receiver ratchets, and the owner of the bound that
// holds regardless of how many senders there are.
//
// Section 5.5 caps the tracked senders at 64 and evicts the OLDEST sender. That is not what this
// does, and the divergence is open item M1-12's labelled recommendation rather than an oversight:
// connect/mls solves the same problem with a bound on the retained keys of the WHOLE table, so
// adding senders adds no memory, and evicts from the FULLEST window, so a member holding a
// handful of skipped keys never pays for a member holding a thousand. Section 5.5's rule starves
// whoever went quiet, which is the member most likely to need the window. Section 14 open item 7
// is what has to finalise this and it blocks the A6 freeze; the number is a constructor parameter
// for that reason.
//
// A ratchet is TRACKED and never auto-created, which is what keeps the table's size a fact about
// the group rather than a choice an attacker makes. connect/mls's own pruneRetained exists
// because its ReceiverKey materialises a ratchet for any leaf a forged header names; here a
// sender this session has not installed a ratchet for is refused with ErrNoReceiverRatchet, so
// the only unbounded quantity left is the retained keys, which is what the bound below is on.
type ReceiverRatchets struct {
	tableLock sync.Mutex
	ratchets  map[ReceiverRatchetKey]*ReceiverRatchet
	// the number of ratchets ever tracked, which is what stamps each one order so a tie
	// between two equally full windows is broken by something stated rather than by go
	// randomised map iteration.
	tracked       uint64
	retainedBound int
}

// NewReceiverRatchets builds an empty table held to a retained key bound.
func NewReceiverRatchets(retainedBound int) (*ReceiverRatchets, error) {
	if retainedBound <= 0 {
		return nil, fmt.Errorf("%w: retained bound %d", ErrWindowSize, retainedBound)
	}
	return &ReceiverRatchets{
		ratchets:      map[ReceiverRatchetKey]*ReceiverRatchet{},
		retainedBound: retainedBound,
	}, nil
}

// Track installs a ratchet under one key, replacing and erasing whatever was there.
//
// The replaced ratchet is zeroized rather than dropped, because a ratchet replaced at an epoch
// change is holding the previous epoch's rungs and those are exactly the octets forward secrecy
// is about.
func (self *ReceiverRatchets) Track(key ReceiverRatchetKey, ratchet *ReceiverRatchet) {
	self.tableLock.Lock()
	defer self.tableLock.Unlock()
	if replaced, wasTracked := self.ratchets[key]; wasTracked {
		replaced.Zeroize()
	}
	self.tracked += 1
	ratchet.tracked = self.tracked
	self.ratchets[key] = ratchet
}

// KeyFor answers one tracked sender's record key for one stream index, and holds the whole table
// to its retained bound afterwards.
//
// The noinline directive is the convention the two ratchets keep: the prune at the end erases
// through storage that outlives this call. It is also what the derived class demands, because
// that class closes over BARE NAMES and (*ReceiverRatchet).KeyFor is a member -- a widening the
// gate states, and one that costs a pragma rather than accuracy.
//
//go:noinline
func (self *ReceiverRatchets) KeyFor(key ReceiverRatchetKey, index uint64) ([]byte, error) {
	self.tableLock.Lock()
	defer self.tableLock.Unlock()
	ratchet, isTracked := self.ratchets[key]
	if !isTracked {
		return nil, fmt.Errorf("%w: sender %x retention %#02x", ErrNoReceiverRatchet, key.SenderHandle, key.RetentionWire)
	}
	answer, err := ratchet.KeyFor(index)
	if err != nil {
		return nil, err
	}
	self.pruneRetainedLocked()
	return answer, nil
}

// Retained is how many skipped rungs the whole table is holding.
func (self *ReceiverRatchets) Retained() int {
	self.tableLock.Lock()
	defer self.tableLock.Unlock()
	return self.retainedLocked()
}

// Zeroize erases every ratchet in the table.
//
// The noinline directive is the convention again: the erasure is each ratchet's own, reached
// through a method call on a value ranged out of this table.
//
//go:noinline
func (self *ReceiverRatchets) Zeroize() {
	self.tableLock.Lock()
	defer self.tableLock.Unlock()
	for key, ratchet := range self.ratchets {
		ratchet.Zeroize()
		delete(self.ratchets, key)
	}
}

// retainedLocked sums the windows of every ratchet in the table.
//
// The caller holds tableLock.
func (self *ReceiverRatchets) retainedLocked() int {
	retained := 0
	for _, ratchet := range self.ratchets {
		retained += ratchet.Retained()
	}
	return retained
}

// pruneRetainedLocked holds the skipped rungs retained across EVERY ratchet of this table to one
// bound, evicting from the fullest window.
//
// The choice of WHICH window is the half that matters. Evicting the globally oldest rung would
// let one flooding sender push out the handful of keys an honest out of order sender is holding,
// which turns a memory bound into a way to drop other members' messages; taking from the largest
// holder puts the pressure on whoever created it. The tie between two equally full windows is
// broken by the order the two were TRACKED in rather than by go's randomised map iteration, so the
// behaviour can be stated and tested rather than merely bounded. It is not broken by comparing
// the two senders handles: guardrail G8 sends every comparison of octets in this tree through
// subtle.ConstantTimeCompare, which answers equality and cannot answer an ordering, and the rule
// is derived over the whole tree rather than argued case by case.
//
// The caller holds tableLock.
func (self *ReceiverRatchets) pruneRetainedLocked() {
	for self.retainedBound < self.retainedLocked() {
		var fullest *ReceiverRatchet
		fullestHeld := 0
		for _, ratchet := range self.ratchets {
			held := ratchet.Retained()
			if fullest == nil || fullestHeld < held ||
				(fullestHeld == held && ratchet.tracked < fullest.tracked) {
				fullest, fullestHeld = ratchet, held
			}
		}
		if fullest == nil || fullestHeld == 0 {
			// unreachable: the total is the sum of the windows, so a total over the bound
			// means some window is non empty and the fullest is one of those. It is a
			// return and not an assertion because the alternative for a loop whose only
			// exit is the bound would be to spin forever on a state it cannot fix.
			return
		}
		fullest.stateLock.Lock()
		fullest.evictOldestLocked()
		fullest.stateLock.Unlock()
	}
}

// stepRecordKey advances one rung of the ladder and erases the rung it came from.
//
// It is one helper for both resume walks, because the derivation and the erasure belong together:
// RecordKeyNext deliberately does not erase its input -- a receiver filling its window has to
// KEEP the rungs it passes -- so every caller that is walking PAST a rung rather than retaining
// it owes the erasure, and a body that spelled the two lines itself is a body one edit away from
// leaving a whole ladder in the heap.
//
// The noinline directive is this package's erase helper class, reached through the hand-off.
//
//go:noinline
func stepRecordKey(recordKey []byte) []byte {
	successor := RecordKeyNext(recordKey)
	zeroize(recordKey)
	return successor
}
