// GroupSession: the type the whole of spec A section 5.2 hangs off, and which no document
// declares.
//
// THE DESIGN HERE IS THIS PLAN'S AND NOT THE SPEC'S, and that is said first because everything
// below is a decision somebody may want to revisit. Grepping the whole of spec A for
// GroupSession returns three lines: section 5.2's two method signatures, section 3.6's
// concurrency row, and section 5.6's sentence that "the constructor takes the sink to make it
// explicit". There is no struct, no constructor, no statement of what it holds or how it is
// closed -- while section 5.6 silently adds a StreamIndexReserver to that constructor and
// section 5.3 adds an epoch zero storage root it must have persisted since group creation. Open
// item M1-4.
//
// THE CONCURRENCY CONTRACT IS QUOTED, because its shape is the reason it exists. Section 3.6:
//
//	messagegroup.GroupSession -- Safe for concurrent use. Owns exactly one mls.Group and
//	serializes access through a single-goroutine command loop (run(), started by the
//	constructor, per CODESTYLE goroutine lifecycle).
//
//	The command-loop shape matters: MLS commit construction, message ingest, and epoch rotation
//	all mutate the same tree, and a lock around each public method would not prevent an
//	interleaving where two goroutines both build a commit for epoch n. One goroutine per group,
//	commands on a channel.
//
// So there is no stateLock in this file and there must not be one. A mutex around each public
// method satisfies a race detector and NOT the property: two goroutines can each take the lock,
// each read the epoch, each release it and each build a commit for that epoch. Every field below
// is reached from the loop goroutine only, and session_test.go derives the class of methods that
// touch them off the syntax tree rather than trusting this paragraph.
//
// WHAT IT HOLDS AND WHY IT HOLDS THAT, derived from what its consumers need rather than listed:
// one GroupHandle, because section 3.6's "owns exactly one mls.Group" is satisfied by holding the
// INTERFACE whose one production implementation wraps one -- naming *mls.Group in a field here
// would make Gate 5's swap a type change rather than a factory change; the EPOCH ZERO storage
// root, because group_handle_key is derived from it and must not move when the epoch does; the
// current epoch's root, its class keys and its two auth keys; one injected reserver; one sender
// ratchet per retention class and one receiver ratchet table; this device's leaf and the
// sender_handle computed from it; and an injected clock, because expire_at is a clock read and
// connect/mls, connect/message and this package have no timing sensitive test in them.
package messagegroup

import (
	"errors"
	"fmt"
	"sync"

	"github.com/urnetwork/connect/message"
)

// sessionCommand is one unit of work for the loop goroutine.
//
// The action closes over its own results and the poster reads them after done is closed, which
// is the happens-before this shape rests on: the loop writes, closes the channel, and the poster
// reads only after receiving from it.
type sessionCommand struct {
	action func()
	done   chan struct{}
}

// GroupSession is one member's view of one group at one epoch, serialized through one goroutine.
type GroupSession struct {
	// written once by the constructor and read from every goroutine.
	commands chan *sessionCommand
	// closed by run() when the loop has exited, which is what lets a poster tell "the session
	// is closed" from "the loop is busy" without a lock.
	stopped   chan struct{}
	closeOnce sync.Once
	closeErr  error

	// ------------------------------------------------------------------
	// everything below is reached from the loop goroutine ONLY
	// ------------------------------------------------------------------

	// the one MLS surface this session is allowed to see.
	handle GroupHandle
	// set by the Close command, read by the loop to decide whether to return.
	closing bool

	// the epoch zero storage root's expansion, PERSISTED and never recomputed from a later
	// epoch. Section 5.3 fixes group_handle_key at group creation; a session that recomputed it
	// from the current root would give every epoch a different sender_handle, so a member's
	// stream would end at every commit and the server would route the next record nowhere.
	groupHandleKey []byte

	groupId       [32]byte
	epoch         uint64
	ownLeaf       uint32
	senderHandle  [16]byte
	storageRoot   []byte
	classKeys     *ClassKeys
	writeKey      []byte
	readKey       []byte
	serverNonce   []byte
	pqSecret      []byte
	reserver      StreamIndexReserver
	nowMs         func() int64
	windowSize    int
	retainedBound int

	// one sender ladder per retention class wire byte, and one table of the receivers'.
	senders   map[byte]*SenderRatchet
	receivers *ReceiverRatchets
}

// NewGroupSession opens a session over one group handle at the handle's current epoch.
//
// pqSecret is REQUIRED and has no default. It is task 13's to produce and it does not exist yet,
// so wave 1's callers supply one -- which is the shape this project's own rule asks for: "a
// missing key schedule fails closed and looks like what it is; a placeholder one fails open and
// looks like a working messenger." A constructor that defaulted it to thirty two zeros would
// produce a perfectly good storage root, both clients would agree, every test would pass, and the
// PQ half of the design would be silently gone.
//
// storageRootEpoch0 is the root group_handle_key is expanded from and it is PERSISTED state. A
// session opened at epoch 0 may leave it nil, because the current root IS the epoch zero root and
// the constructor derives it; a session opened at any later epoch must supply it, and is refused
// if it does not, because the alternative is a handle key recomputed from the wrong epoch.
//
// The reserver is refused if nil rather than defaulted to an in-memory one. Section 5.6 says the
// constructor takes the sink to make it explicit, and a default in-memory reserver is the exact
// placeholder hazard the CP3a rule forbids: it would lose every reservation at a restart and
// re-issue every stream index under an unmoved class key.
//
// The noinline directive is this package's erase helper class, reached through the epoch install
// it ends with: that install erases the fields it is about to overwrite, and those stores outlive
// this call.
//
//go:noinline
func NewGroupSession(handle GroupHandle, pqSecret []byte, storageRootEpoch0 []byte,
	reserver StreamIndexReserver, nowMs func() int64, serverNonce []byte) (*GroupSession, error) {

	if handle == nil {
		return nil, fmt.Errorf("%w: the epoch's mls_secret is exported through it", ErrNilGroupHandle)
	}
	if reserver == nil {
		return nil, fmt.Errorf("%w: section 5.6 has the constructor take the sink to make it explicit", ErrNilStreamIndexReserver)
	}
	if nowMs == nil {
		return nil, fmt.Errorf("%w: expire_at is a clock read", ErrNilClock)
	}
	if len(serverNonce) == 0 {
		return nil, fmt.Errorf("%w: write_auth is a mac over it", ErrSessionServerNonce)
	}
	if len(pqSecret) == 0 {
		return nil, fmt.Errorf("%w: task 13 produces it and there is no default", ErrNilPqSecret)
	}
	groupId := handle.GroupId()
	if len(groupId) != len(([32]byte{})) {
		return nil, fmt.Errorf("%w: the group id is %d octets and a record header carries %d",
			ErrRecordNotForThisSession, len(groupId), len([32]byte{}))
	}
	self := &GroupSession{
		commands:      make(chan *sessionCommand),
		stopped:       make(chan struct{}),
		handle:        handle,
		reserver:      reserver,
		nowMs:         nowMs,
		serverNonce:   append([]byte(nil), serverNonce...),
		pqSecret:      append([]byte(nil), pqSecret...),
		windowSize:    DefaultRecordWindowSize,
		retainedBound: DefaultRetainedRecordKeys,
		senders:       map[byte]*SenderRatchet{},
	}
	self.groupId = [32]byte(groupId)
	self.ownLeaf = handle.OwnLeafIndex()
	self.epoch = handle.Epoch()
	receivers, err := NewReceiverRatchets(self.retainedBound)
	if err != nil {
		return nil, err
	}
	self.receivers = receivers
	if err := self.installEpochOnLoop(storageRootEpoch0); err != nil {
		return nil, err
	}
	// the loop starts LAST, after every field it will read is written, so there is no window
	// in which the loop goroutine observes a half built session.
	go self.run()
	return self, nil
}

// run is the one goroutine that touches this session's state.
//
// It exits when a command sets closing, and it closes stopped on the way out so that a poster
// blocked on the send in do() is released rather than deadlocked.
func (self *GroupSession) run() {
	defer close(self.stopped)
	for {
		select {
		case command := <-self.commands:
			command.action()
			close(command.done)
			if self.closing {
				return
			}
		case <-self.stopped:
			// unreachable: only this goroutine closes stopped, and it does so on the way
			// out. It is here so that a future second closer of that channel cannot turn
			// this loop into a spin.
			return
		}
	}
}

// do runs one action on the loop goroutine and waits for it.
//
// EVERY PUBLIC METHOD THAT TOUCHES SESSION STATE GOES THROUGH THIS, and session_test.go derives
// that class off the syntax tree rather than listing it. A method that read a field directly
// would be reading state another goroutine is writing, and a mutex around it would satisfy the
// race detector while leaving section 3.6's actual property -- one decision per epoch -- unheld.
func (self *GroupSession) do(action func()) error {
	command := &sessionCommand{action: action, done: make(chan struct{})}
	select {
	case self.commands <- command:
	case <-self.stopped:
		return ErrSessionClosed
	}
	<-command.done
	return nil
}

// Close stops the loop and erases every key this session holds.
//
// It is idempotent, and the second call answers the first call's error rather than a new one: a
// deferred Close beside an explicit one is not a mistake, and a second Close that refused would
// make the ordinary defer a failure.
//
// It returns only after the loop goroutine has exited, so a goroutine accounting test sees a
// leaked loop as a failure rather than as a slow test.
func (self *GroupSession) Close() error {
	self.closeOnce.Do(func() {
		postErr := self.do(func() {
			self.closing = true
			self.zeroizeOnLoop()
			self.closeErr = self.handle.Close()
		})
		if postErr != nil && !errors.Is(postErr, ErrSessionClosed) {
			self.closeErr = postErr
		}
	})
	<-self.stopped
	return self.closeErr
}

// Epoch is the epoch this session is at.
func (self *GroupSession) Epoch() uint64 {
	var epoch uint64
	if err := self.do(func() { epoch = self.epoch }); err != nil {
		return 0
	}
	return epoch
}

// SenderHandle is the handle this session's own records are routed by.
func (self *GroupSession) SenderHandle() ([16]byte, error) {
	var handle [16]byte
	var err error
	if postErr := self.do(func() {
		if self.closing {
			err = ErrSessionClosed
			return
		}
		handle = self.senderHandle
	}); postErr != nil {
		return [16]byte{}, postErr
	}
	return handle, err
}

// AdvanceEpoch installs the epoch the handle is now at, with a fresh pq_secret.
//
// GROUP_HANDLE_KEY DOES NOT MOVE. It is expanded from the epoch zero root, which this session
// persisted at construction, and the whole reason it is persisted is that recomputing it from
// the current root is a one line "simplification" that changes every sender_handle in the group
// at every commit.
//
// Every ratchet is dropped and zeroized. A ratchet held across an epoch is holding the previous
// epoch's rungs, which are exactly the octets forward secrecy is about, and the class keys it
// was built from have moved.
//
// The noinline directive is this package's erase helper class: pq_secret is erased here, in this
// body, before it is overwritten.
//
//go:noinline
func (self *GroupSession) AdvanceEpoch(pqSecret []byte) error {
	var err error
	if postErr := self.do(func() {
		if self.closing {
			err = ErrSessionClosed
			return
		}
		if len(pqSecret) == 0 {
			err = fmt.Errorf("%w: task 13 produces it and there is no default", ErrNilPqSecret)
			return
		}
		// erased before it is overwritten, in this body, for installEpochOnLoop's reason.
		replacement := append([]byte(nil), pqSecret...)
		zeroize(self.pqSecret)
		self.pqSecret = replacement
		err = self.installEpochOnLoop(self.groupHandleKey)
	}); postErr != nil {
		return postErr
	}
	return err
}

// TrackSender installs a receiver ratchet for one peer's ladder in one retention class.
//
// headIndex is the ladder position this receiver starts at and it is the CALLER'S state, never a
// number read off a record header: NewReceiverRatchet walks one expansion per index below it, so
// a peer that could choose this number could choose how much work this session does. The walk is
// bounded by maxLadderWalk in any case, which is the second half of the same argument.
func (self *GroupSession) TrackSender(leaf uint32, class message.RetentionClass, ephBucket uint8,
	headIndex uint64) error {

	var err error
	if postErr := self.do(func() {
		if self.closing {
			err = ErrSessionClosed
			return
		}
		err = self.trackSenderOnLoop(leaf, class, ephBucket, headIndex)
	}); postErr != nil {
		return postErr
	}
	return err
}

// trackSenderOnLoop is TrackSender's body. The caller is the loop goroutine.
func (self *GroupSession) trackSenderOnLoop(leaf uint32, class message.RetentionClass,
	ephBucket uint8, headIndex uint64) error {

	retentionWire, err := message.RetentionClassWire(class, ephBucket)
	if err != nil {
		return err
	}
	classKey, err := self.classKeyOnLoop(class)
	if err != nil {
		return err
	}
	ratchet, err := NewReceiverRatchet(classKey, leaf, headIndex, self.windowSize)
	if err != nil {
		return err
	}
	self.receivers.Track(ReceiverRatchetKey{
		SenderHandle:  SenderHandle(self.groupHandleKey, leaf),
		RetentionWire: retentionWire,
	}, ratchet)
	return nil
}

// installEpochOnLoop derives every key of the epoch the handle is at.
//
// storageRootEpoch0 is nil only when the handle is at epoch 0, and the refusal for every other
// epoch is what makes group_handle_key persisted state rather than a value this function could
// invent. An aged out epoch is reported and never silently zero: mls.ErrEpochErased comes back
// out of Export and travels, because a storage root computed over an empty exporter output is
// thirty two well formed octets that no other member ever reproduces.
//
// The caller is the loop goroutine, or the constructor before the loop exists.
//
// The noinline directive is this package's erase helper class: every field this body overwrites is
// erased in it first, and those stores are the receiver's own.
//
//go:noinline
func (self *GroupSession) installEpochOnLoop(storageRootEpoch0 []byte) error {
	mlsSecret, err := self.handle.Export(mlsSecretLabel, nil, mlsSecretBytes)
	if err != nil {
		return fmt.Errorf("messagegroup: this session could not export its epoch's mls_secret: %w", err)
	}
	defer zeroize(mlsSecret)
	self.epoch = self.handle.Epoch()
	self.ownLeaf = self.handle.OwnLeafIndex()
	root := StorageRoot(mlsSecret, self.pqSecret)
	handleKey := []byte(nil)
	switch {
	case 0 < len(storageRootEpoch0):
		// a COPY, taken before the erase below, because AdvanceEpoch passes this session's own
		// group_handle_key back in: erasing the field first would erase the argument.
		handleKey = append([]byte(nil), storageRootEpoch0...)
	case self.epoch == 0:
		handleKey = GroupHandleKey(root)
	default:
		return fmt.Errorf("%w: this handle is at epoch %d and no epoch zero group handle key was given",
			ErrEpochZeroRootMissing, self.epoch)
	}
	// EVERY FIELD IS ERASED HERE, IN THIS BODY, IMMEDIATELY BEFORE IT IS OVERWRITTEN. It is
	// spelled out rather than delegated to zeroizeOnLoop for the reason that method's own comment
	// gives: connect/mls reads a drop site as a WRITE to a field holding key material, and it
	// follows no delegation, so an epoch rotation that called a helper would read there as a
	// complete second epoch dropped into the heap for the collector to move around.
	for _, ratchet := range self.senders {
		ratchet.Zeroize()
	}
	if self.receivers != nil {
		self.receivers.Zeroize()
	}
	self.classKeys.Zeroize()
	zeroize(self.storageRoot)
	zeroize(self.writeKey)
	zeroize(self.readKey)
	zeroize(self.groupHandleKey)
	self.groupHandleKey = handleKey
	self.storageRoot = root
	self.classKeys = DeriveClassKeys(root)
	self.writeKey = message.WriteKey(root)
	self.readKey = message.ReadKey(root)
	self.senderHandle = SenderHandle(self.groupHandleKey, self.ownLeaf)
	self.senders = map[byte]*SenderRatchet{}
	return nil
}

// classKeyOnLoop is the class key one retention class seals under.
//
// The eph classes are deliberately absent from ClassKeys -- MASTER invariant I4 -- so they are a
// refusal here rather than a fourth field, and the refusal is the same one SealRecord makes for
// every class that is not DURABLE.
//
// The caller is the loop goroutine.
func (self *GroupSession) classKeyOnLoop(class message.RetentionClass) ([]byte, error) {
	if self.classKeys == nil {
		return nil, ErrSessionClosed
	}
	switch class {
	case message.RetentionPermanent:
		return self.classKeys.Perm, nil
	case message.RetentionDurable:
		return self.classKeys.Durable, nil
	case message.RetentionMedia:
		return self.classKeys.Media, nil
	}
	return nil, fmt.Errorf("%w: retention class %d has no class key at all", ErrRetentionClassUnruled, class)
}

// senderRatchetOnLoop is this session's own ladder for one retention class, built on first use.
//
// The stream it reserves in carries the group, this session's sender_handle and the retention
// class wire byte, which is StreamKey's whole subject: a reserver keyed on the group alone would
// let one class of this group consume the index the next class is about to reserve, and the
// second class would then be refused forever.
//
// The caller is the loop goroutine.
func (self *GroupSession) senderRatchetOnLoop(class message.RetentionClass, retentionWire byte) (*SenderRatchet, error) {
	if ratchet, isBuilt := self.senders[retentionWire]; isBuilt {
		return ratchet, nil
	}
	classKey, err := self.classKeyOnLoop(class)
	if err != nil {
		return nil, err
	}
	ratchet, err := NewSenderRatchet(classKey, self.ownLeaf, StreamKey{
		GroupId:       self.groupId,
		SenderHandle:  self.senderHandle,
		RetentionWire: retentionWire,
	}, self.reserver)
	if err != nil {
		return nil, err
	}
	self.senders[retentionWire] = ratchet
	return ratchet, nil
}

// zeroizeOnLoop erases everything this session holds, and it is THE erase of this type.
//
// Every field is named here rather than delegated to the partial erase above, and that is a gate
// rather than a preference: connect/mls reads an erase FIELD BY FIELD off the source and follows
// no delegation, so a body that called zeroizeEpochOnLoop and added the two survivors would read
// there as an erase of two fields. The duplication is what makes the reading true.
//
// The caller is the loop goroutine.
//
//go:noinline
func (self *GroupSession) zeroizeOnLoop() {
	for _, ratchet := range self.senders {
		ratchet.Zeroize()
	}
	if self.receivers != nil {
		self.receivers.Zeroize()
	}
	self.classKeys.Zeroize()
	zeroize(self.storageRoot)
	zeroize(self.writeKey)
	zeroize(self.readKey)
	zeroize(self.groupHandleKey)
	zeroize(self.pqSecret)
	self.classKeys = nil
	self.storageRoot = nil
	self.writeKey = nil
	self.readKey = nil
	self.groupHandleKey = nil
	self.pqSecret = nil
	self.senders = map[byte]*SenderRatchet{}
}

// The exporter label and length MASTER section 7 derives mls_secret at.
//
// They are constants of this file rather than arguments because there is exactly one mls_secret
// per epoch and a second label would be a second storage root: every key of the epoch hangs off
// it, so two callers exporting under two labels would be two members of one group who agree
// about nothing.
const (
	mlsSecretLabel = "URmessage/v1/storage"
	mlsSecretBytes = 32
)
