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
// WHAT THE CONSTRUCTOR IS HANDED FOR EPOCH ZERO IS THE GROUP HANDLE KEY AND NOT THE ROOT, and the
// two are one HKDF-Expand apart and both thirty two octets, so the name is the only thing telling
// them apart. Section 5.3's own sentence is about the ROOT -- it says a session past epoch zero
// must have persisted storage_root[0] -- and this file diverges from it deliberately: MASTER
// section 8 says what a member has to HOLD is group_handle_key ("a member that does not hold it
// cannot compute its own handle and therefore cannot write"), and storage_root[0] is strictly more
// than that. Every class key, the write key and the read key of epoch zero hang off the root, so a
// device that persisted it for the life of the group would be persisting epoch zero's whole key
// schedule forever -- the exact material forward secrecy is about -- to recover a routing
// identifier every member already knows. So the persisted value is the EXPANSION, the parameter is
// named for it, and both branches of installEpochOnLoop end holding the same kind of thing. Open
// item M1-4 carries the divergence.
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

	// group_handle_key: the epoch zero storage root's expansion, PERSISTED and never recomputed
	// from a later epoch. Section 5.3 fixes it at group creation; a session that recomputed it
	// from the current root would give every epoch a different sender_handle, so a member's
	// stream would end at every commit and the server would route the next record nowhere.
	//
	// It is what the constructor takes and what AdvanceEpoch hands back, so the value in this
	// field, the value the parameter names and the value the epoch zero branch derives are one
	// kind of thing. They were not: the parameter was named for the ROOT and used verbatim as
	// this key, so a device persisting what the doc told it to persist computed a different
	// sender_handle than its own group after every restart at epoch > 0.
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
// pqSecret is REQUIRED and has no default. NewPqSecret in epoch.go is what draws it -- task 13
// landed it, and this sentence used to say it did not exist -- and a caller that has one supplies
// it here; which is the shape this project's own rule asks for: "a
// missing key schedule fails closed and looks like what it is; a placeholder one fails open and
// looks like a working messenger." A constructor that defaulted it to thirty two zeros would
// produce a perfectly good storage root, both clients would agree, every test would pass, and the
// PQ half of the design would be silently gone. Its WIDTH is refused here as well as its absence,
// and separately, because until the review of task 13 this door checked only that the value was
// non empty: MASTER section 7 fixes pq_secret[n] at thirty two octets, and a four octet one is the
// ikm of a storage_root that is well formed, agreed by both clients and weaker than the document
// specifies -- which no round trip in this package could ever tell you.
//
// groupHandleKeyEpoch0 IS group_handle_key -- HKDF-Expand(storage_root[0], "gh/v1", 32) -- and it
// is PERSISTED state. A session opened at epoch 0 may leave it nil, because the current root IS
// the epoch zero root and the constructor expands it; a session opened at any later epoch must
// supply it, and is refused if it does not, because the alternative is a handle key recomputed
// from the wrong epoch. It is the KEY and not the root it came from, for the reason the file
// comment gives: the root is epoch zero's whole key schedule and this is a routing identifier.
// A value of any other width is refused with a typed error rather than left to panic out of the
// first expansion that meets it, which is what a value decoded out of durable storage deserves.
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
func NewGroupSession(handle GroupHandle, pqSecret []byte, groupHandleKeyEpoch0 []byte,
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
		return nil, fmt.Errorf("%w: NewPqSecret draws one and there is no default", ErrNilPqSecret)
	}
	if len(pqSecret) != PqSecretBytes {
		return nil, fmt.Errorf("%w: %d octets, and it is the ikm of every storage_root this session extracts",
			ErrPqSecretLength, len(pqSecret))
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
	if err := self.installEpochOnLoop(groupHandleKeyEpoch0); err != nil {
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
		// the handle's own error is carried out on a LOCAL and written to the field here,
		// off the loop, on purpose: closeErr is the only field of this session no command
		// touches, and a field the loop writes is one nothing may read afterwards without
		// posting -- which is what the shape gate in session_test.go derives and what a
		// close that stored its answer from inside the command would quietly break.
		closed := error(nil)
		postErr := self.do(func() {
			self.closing = true
			self.zeroizeOnLoop()
			closed = self.handle.Close()
		})
		self.closeErr = closed
		if postErr != nil && !errors.Is(postErr, ErrSessionClosed) {
			self.closeErr = postErr
		}
	})
	<-self.stopped
	return self.closeErr
}

// Epoch is the epoch this session is at.
//
// It answers an error rather than a zero, because a closed session's zero is indistinguishable
// from epoch 0 -- which is the epoch every group spends its first commit in, so the ambiguity is
// over the value a caller is most likely to meet. SenderHandle one method down already answers
// this shape and for the same reason.
func (self *GroupSession) Epoch() (uint64, error) {
	var epoch uint64
	var err error
	if postErr := self.do(func() {
		if self.closing {
			err = ErrSessionClosed
			return
		}
		epoch = self.epoch
	}); postErr != nil {
		return 0, postErr
	}
	return epoch, err
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

// EpochKeys is this session's write_key and read_key for the epoch it is at, copied out of the
// loop's own fields into a value the caller owns and destroys.
//
// THIS IS THE ONLY DOOR ONTO EITHER KEY, and the reason it is a door rather than two fields is in
// epochkeys.go's header: the alternative is a second assembly of one preimage, which is the defect
// this package has already paid for once. Both keys are the MESSAGE SERVER's, not a member's:
// write_auth on a submit is macced under the first and req_auth on a fetch is macced under the
// second, and connect/message's ComputeWriteAuth and ComputeRequestAuth are what spend them.
// Authenticity between MEMBERS is mls's and is not this pair's job at any point -- MASTER section
// 9.2 says so in as many words, and says that the server holds write_key itself.
//
// THE VALUE IS THE CALLER'S AND SO IS THE ERASE. Destroy it, and destroy it in a defer: this
// session's own copies are erased at the next AdvanceEpoch and at Close, and neither of those
// reaches a value this method already handed out.
//
// The copies are taken INSIDE the posted command, which is where they have to be taken: the two
// fields are written and zeroized by the loop goroutine, so a copy made off the loop is a read
// racing a write rather than a copy of anything in particular.
//
// THE self.closing CHECK BELOW IS UNREACHABLE, and it is written anyway, in the shape the six
// siblings of this file and the two of seal.go use. Measured rather than asserted: run exits the
// moment a command sets closing, and Close's command is the only one that sets it, so no second
// command can ever observe the flag -- every later caller is refused by do's own send, which sees
// stopped closed. Deleting this clause survives an unfiltered run of this package, and so does
// deleting Epoch's and SenderHandle's, which is what says the hole is the pattern's and not this
// method's. It stays because it is what fails closed if run ever stops exiting on the first
// closing command, and because a door here that alone omitted it would read as a decision.
func (self *GroupSession) EpochKeys() (*EpochKeys, error) {
	var keys *EpochKeys
	var err error
	if postErr := self.do(func() {
		if self.closing {
			err = ErrSessionClosed
			return
		}
		keys = newEpochKeys(self.epoch, self.readKey, self.writeKey)
	}); postErr != nil {
		return nil, postErr
	}
	return keys, err
}

// AdvanceEpoch installs the epoch the handle is now at, with a fresh pq_secret.
//
// GROUP_HANDLE_KEY DOES NOT MOVE. It was expanded from the epoch zero root ONCE, and what this
// session has held since construction is that answer rather than the root -- so there is nothing
// here to re-expand and the field is handed straight back to the install. The whole reason it is
// persisted is that recomputing it from the current root is a one line "simplification" that
// changes every sender_handle in the group at every commit.
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
			err = fmt.Errorf("%w: NewPqSecret draws one and there is no default", ErrNilPqSecret)
			return
		}
		if len(pqSecret) != PqSecretBytes {
			err = fmt.Errorf("%w: %d octets, and it is the ikm of the storage_root of the epoch this session is moving into",
				ErrPqSecretLength, len(pqSecret))
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

// RebindServerNonce replaces the nonce this session macs write_auth under, which the submitting
// connection chooses afresh at every Hello.
//
// WHY THERE IS A SETTER AT ALL. serverNonce was fixed at construction and there was no way to
// move it, so the first reconnect invalidated every record this session had sealed since: spec A
// section 5.7 has the server draw a fresh thirty two octet nonce per connection and carry it in
// HelloResponse, and write_auth is a mac over it. A session that outlived one connection was
// wrong, and this is S2-2.
//
// THE BLAST RADIUS, MEASURED RATHER THAN ASSERTED, because a setter on a key schedule field
// invites the larger reading. self.serverNonce is read in this package's production source at
// exactly ONE site -- seal.go's authenticate, which hands it to message.ComputeWriteAuth -- and
// that call's answer lands in record.WriteAuth and in nothing else. It is not an input to
// AADHead, to AADBody, to either record aead derivation, to StorageRoot, to DeriveClassKeys, to
// WriteKey, to ReadKey, to SenderHandle or to StreamKey. So ONE sealed value binds it, a rebind
// must recompute that one value on every record not yet submitted -- which is ReauthRecord in
// seal.go -- and NOTHING ALREADY SEALED BECOMES UNOPENABLE: the open path never reads write_auth
// at all, which openRecordOnLoop's own body is the evidence for. connect/message's
// ComputeRequestAuth binds the nonce too, and req_auth has no caller in this package.
//
// THE SUPERSEDED VALUE IS ERASED BEFORE IT IS OVERWRITTEN AND THE NONCE IS NOT A KEY. Both
// halves of that are true and the discipline is the file's rather than the value's: spec A hands
// this nonce to the server in the clear, so nothing here is protecting it, and a field of this
// type dropped unerased is a drop site that reads exactly like the ones that are protecting
// something. AdvanceEpoch erases pq_secret in its own body for the same reason and in the same
// shape, and no property of this package observes either erase.
//
// THE REFUSAL IS THE CONSTRUCTOR'S OWN SENTINEL AND THE CONSTRUCTOR'S OWN RULE. An empty or nil
// nonce is refused with ErrSessionServerNonce, which is what NewGroupSession refuses an empty one
// with; and a nonce of any non-empty WIDTH is accepted here because the constructor accepts one.
// Two doors onto one field with two rules is two rules, and a reader meeting a thirty one octet
// nonce would have to derive which door it came through. MASTER section 7 and spec A section 5.7
// both fix the width at thirty two and this package checks neither -- the disagreement is real,
// is not this method's to rule, and is open item K1-2.
//
// THERE IS NO GETTER, and that is a narrowing rather than an omission. A caller that rebinds
// already holds the nonce: it came out of HelloResponse in the same call that prompted the
// rebind, so a getter answers a question nobody asks. What it would cost is precise --
// keysource_test.go's reproduction is handed server_nonce as one of its three INJECTED values,
// and a getter is the one thing that would let a fixture hand it the nonce the session holds
// instead, at which point the third input stops being independent and the subject starts agreeing
// with itself. noncerebind_test.go derives that class off the syntax tree and prints its
// complement.
//
// THE self.closing CHECK BELOW IS UNREACHABLE, in the shape and for the reason EpochKeys's
// comment measures: run returns on the first command that sets closing and commands is
// unbuffered, so no second command observes the flag and every later caller is refused by do's
// own send. It is written anyway because it fails closed, and no property here claims it is
// driven -- a closed session's refusal comes back out of do.
//
// The noinline directive is this package's erase helper class, reached through the zeroize
// below: that store lands in an array this call does not hold the only reference to.
//
//go:noinline
func (self *GroupSession) RebindServerNonce(serverNonce []byte) error {
	var err error
	if postErr := self.do(func() {
		if self.closing {
			err = ErrSessionClosed
			return
		}
		if len(serverNonce) == 0 {
			err = fmt.Errorf("%w: write_auth is a mac over it", ErrSessionServerNonce)
			return
		}
		// a COPY, and erased before it is overwritten, in this body, for AdvanceEpoch's
		// reason. The argument is the CALLER'S buffer: a session that retained it would seal
		// under whatever that buffer became after this call returned.
		replacement := append([]byte(nil), serverNonce...)
		zeroize(self.serverNonce)
		self.serverNonce = replacement
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
// groupHandleKeyEpoch0 is nil only when the handle is at epoch 0, and the refusal for every other
// epoch is what makes group_handle_key persisted state rather than a value this function could
// invent. An aged out epoch is reported and never silently zero: mls.ErrEpochErased comes back
// out of Export and travels, because a storage root computed over an empty exporter output is
// thirty two well formed octets that no other member ever reproduces.
//
// BOTH BRANCHES END HOLDING THE SAME KIND OF VALUE, which is the whole of what the switch below
// is for and is what it did not do. One arm took the argument VERBATIM and the other expanded a
// root through GroupHandleKey; both answers are thirty two octets, so nothing refused the
// disagreement, and a device restarted at epoch > 0 with the value its own doc told it to persist
// computed a sender_handle no peer computes and no peer's ReceiverRatchetKey matches. The argument
// is the KEY, so the epoch zero arm is the only one that expands anything.
//
// The caller is the loop goroutine, or the constructor before the loop exists.
//
// The noinline directive is this package's erase helper class: every field this body overwrites is
// erased in it first, and those stores are the receiver's own.
//
//go:noinline
func (self *GroupSession) installEpochOnLoop(groupHandleKeyEpoch0 []byte) error {
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
	case 0 < len(groupHandleKeyEpoch0):
		// the width is refused HERE rather than at the first expansion that meets it. A
		// persisted value comes out of durable storage, so sixty four octets is its plausible
		// wrong shape, and SenderHandle's refusal is a panic carrying the sentinel -- which
		// would surface on the caller's goroutine out of a constructor whose every other
		// refusal is a typed error.
		if len(groupHandleKeyEpoch0) != groupHandleKeyBytes {
			return fmt.Errorf("%w: %d octets, want %d", ErrGroupHandleKeyLength,
				len(groupHandleKeyEpoch0), groupHandleKeyBytes)
		}
		// a COPY, taken before the erase below, because AdvanceEpoch passes this session's own
		// group_handle_key back in: erasing the field first would erase the argument.
		handleKey = append([]byte(nil), groupHandleKeyEpoch0...)
	case self.epoch == 0:
		// the ONE expansion, and the only branch that has a root to expand. What it produces is
		// the same kind of value the branch above is handed, which is what makes the two arms
		// agree about what this parameter is.
		handleKey = GroupHandleKey(root)
	default:
		return fmt.Errorf("%w: this handle is at epoch %d and no epoch zero group handle key was given",
			ErrEpochZeroHandleKeyMissing, self.epoch)
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
// THE LADDER IS PER CLASS AND THE COUNTER IS NOT, which is ruling A1 as it lands on this file.
// The map below is keyed by the retention wire byte because record_key[0] binds the CLASS KEY, so
// each class is a different ladder and always was. The stream those ladders reserve in carries
// only the group and this session's sender_handle -- no class -- because that is the counter spec
// B's schema, spec B's Q7 and the shipped message server all keep. A stream key that carried the
// class would make this client the only party in the system counting per class, and the server
// would refuse the first record of the second class as a stream index regression.
//
// What used to make that safe here was the retention byte in the key; what makes it safe now is
// that Reserve ALLOCATES, so no two of these ladders can be handed the same index. See
// StreamKey's comment for the ruling and SenderRatchet.Next for the shape.
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
		GroupId:      self.groupId,
		SenderHandle: self.senderHandle,
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
