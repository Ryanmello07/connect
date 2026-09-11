// The fixture every session, seal and engine case is built on: a REAL connect/mls group behind
// the real adapter, and nothing standing in for a key.
//
// THAT IS THE POINT AND IT IS THE MILESTONE'S. CP3b's bar is "every key real, no test-only key
// source anywhere on the path", and a stub GroupHandle answering a made up exporter output would
// satisfy every case in this package while leaving that bar exactly as far away as it was before
// task 9a. So the fixture builds an mls.CryptoProvider, an mls.StateStore, a signature key pair
// and an X-Wing leaf key, founds a group through NewConnectMlsEngine, and hands the session the
// adapter over it. Every KEY on that path is the real one.
//
// FOUR VALUES HERE ARE THE TEST'S AND NOT THE PRODUCT'S, named rather than left for a reader to
// find: pq_secret, which NewPqSecret draws and which the session takes as a required argument with
// no default -- absent rather than defaulted, which is the discipline this project's own rule
// states; the state store, which is a map and persists nothing; the clock, which is a constant
// because this package has no timing sensitive test and must not gain one; and the server nonce,
// which the submitting connection chooses and there is no connection. None of the four is a KEY,
// which is the distinction CP3b's "no test-only key source anywhere on the path" draws.
//
// The state store is in memory and is test-only by construction: it is declared in a _test.go
// file, so no production build of this package can reach it, and imports_test.go's pin over the
// production import set is what keeps a durable one from arriving here instead.
package messagegroup

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/mls"
)

// memoryStateStore is mls.StateStore in a map. It persists nothing and it is not meant to: what
// a case here needs is a store that answers what it was given within one process.
type memoryStateStore struct {
	lock        sync.Mutex
	groupStates map[string][]byte
	privateKeys map[string][]byte
	keyPackages map[string][3][]byte
}

func newMemoryStateStore() *memoryStateStore {
	return &memoryStateStore{
		groupStates: map[string][]byte{},
		privateKeys: map[string][]byte{},
		keyPackages: map[string][3][]byte{},
	}
}

func (self *memoryStateStore) PutGroupState(groupId []byte, epoch uint64, state []byte) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	self.groupStates[fmt.Sprintf("%x/%d", groupId, epoch)] = append([]byte(nil), state...)
	return nil
}

func (self *memoryStateStore) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	state, isHeld := self.groupStates[fmt.Sprintf("%x/%d", groupId, epoch)]
	if !isHeld {
		return nil, fmt.Errorf("no group state for %x at epoch %d", groupId, epoch)
	}
	return append([]byte(nil), state...), nil
}

func (self *memoryStateStore) DeleteGroupStateBefore(groupId []byte, epoch uint64) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	for at := uint64(0); at < epoch; at += 1 {
		delete(self.groupStates, fmt.Sprintf("%x/%d", groupId, at))
	}
	return nil
}

func (self *memoryStateStore) PutPrivateKey(pub []byte, priv []byte) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	self.privateKeys[fmt.Sprintf("%x", pub)] = append([]byte(nil), priv...)
	return nil
}

func (self *memoryStateStore) GetPrivateKey(pub []byte) ([]byte, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	priv, isHeld := self.privateKeys[fmt.Sprintf("%x", pub)]
	if !isHeld {
		return nil, fmt.Errorf("no private key for %x", pub)
	}
	return append([]byte(nil), priv...), nil
}

func (self *memoryStateStore) DeletePrivateKey(pub []byte) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	delete(self.privateKeys, fmt.Sprintf("%x", pub))
	return nil
}

func (self *memoryStateStore) PutKeyPackage(ref []byte, kp []byte, initPriv []byte, encPriv []byte) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	self.keyPackages[fmt.Sprintf("%x", ref)] = [3][]byte{
		append([]byte(nil), kp...), append([]byte(nil), initPriv...), append([]byte(nil), encPriv...),
	}
	return nil
}

func (self *memoryStateStore) TakeKeyPackage(ref []byte) ([]byte, []byte, []byte, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	held, isHeld := self.keyPackages[fmt.Sprintf("%x", ref)]
	if !isHeld {
		return nil, nil, nil, fmt.Errorf("no key package for %x", ref)
	}
	delete(self.keyPackages, fmt.Sprintf("%x", ref))
	return held[0], held[1], held[2], nil
}

// testEngine is one device: its provider, its store, its identity and the engine over them.
type testEngine struct {
	engine      GroupEngine
	crypto      mls.CryptoProvider
	store       *memoryStateStore
	identityPub []byte
	leafKeys    []byte
	// THE PUBLIC HALF OF THE KEY THIS DEVICE SIGNS WITH, which is a different value from
	// identityPub after this fixture's own repair below. Without it a gate asserting "the leaf
	// names the device signer" has nothing to compare the leaf against: testEngine retained the
	// credential identity and neither the signer nor its public half.
	signerPub []byte
	// the store the engine was actually built over, which is memoryStateStore for every fixture
	// but the ones that hand it an observation instrument.
	outerStore mls.StateStore
}

// newTestEngine builds one device's engine, with a real signature key pair and a real X-Wing
// public half in its leaf keys extension.
func newTestEngine(t *testing.T) *testEngine {
	t.Helper()
	engine, err := buildTestEngine()
	if err != nil {
		t.Fatalf("build the engine: %v", err)
	}
	return engine
}

// buildTestEngine is newTestEngine without a *testing.T, because the one way ladder probes in
// recordkey_test.go are plain functions and still have to run on the real thing.
func buildTestEngine() (*testEngine, error) {
	memory := newMemoryStateStore()
	return buildTestEngineOver(memory, memory)
}

// buildTestEngineOver is buildTestEngine with the store chosen by the caller, so that a gate can
// put an observation instrument where the engine's store goes without replacing the one every
// other case runs on. memory is the same store unless the instrument wraps one.
func buildTestEngineOver(store mls.StateStore, memory *memoryStateStore) (*testEngine, error) {
	crypto, err := mls.NewCryptoProvider(mls.CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		return nil, err
	}
	signer, signerPub, err := crypto.SignatureKeyPair()
	if err != nil {
		return nil, err
	}
	// A SECOND, INDEPENDENT DRAW FOR THE CREDENTIAL IDENTITY, and it is the smaller half of j1
	// task 4 that matters most. This fixture used to draw signer and identityPub from ONE
	// SignatureKeyPair call and pass mls.BasicCredential(identityPub) -- so the device's credential
	// identity WAS its signer's public half, and under that fixture the assertion "the leaf names
	// the device signer" and the assertion "the leaf names the credential" are the same program. A
	// gate written over it cannot fail for the reason task 4 exists.
	//
	// Blast radius, measured: identityPub appears on 14 lines of this package's tests, and the only
	// one that compares the two is engine_test.go's MemberAt(0) case, which reads
	// Credential.Identity and stays true.
	_, identityPub, err := crypto.SignatureKeyPair()
	if err != nil {
		return nil, err
	}
	xwingPrivate, err := XwingGenerateKey(bytes.NewReader(crypto.Random(XwingSeedSize)))
	if err != nil {
		return nil, err
	}
	leafKeys, err := (&mls.LeafKeysExtension{
		AlgId:          mls.AlgIdXwing,
		DeviceXwingPub: xwingPrivate.Public().Bytes(),
	}).Encode()
	if err != nil {
		return nil, err
	}
	engine, err := NewConnectMlsEngine(crypto, store, signer,
		mls.BasicCredential(identityPub), leafKeys.ExtensionData)
	if err != nil {
		return nil, err
	}
	return &testEngine{
		engine:      engine,
		crypto:      crypto,
		store:       memory,
		identityPub: append([]byte(nil), identityPub...),
		leafKeys:    leafKeys.ExtensionData,
		signerPub:   append([]byte(nil), signerPub...),
		outerStore:  store,
	}, nil
}

// ---------------------------------------------------------------------------
// the two observation instruments j1 task 4 builds, and neither is a store
// ---------------------------------------------------------------------------

// storeCall is one call this device's engine made into its store: the method, and a COPY of every
// byte argument it was handed, in order.
//
// The arity half of "what reaches the store is unchanged" reads this and not the map.
// memoryStateStore holds two maps and records nothing, so a body that persisted a FIFTH value
// through a second store method leaves a keyPackages entry that still looks exactly right.
type storeCall struct {
	method string
	args   [][]byte
}

// recordingAliasStore is mls.StateStore as an OBSERVATION INSTRUMENT and not as a store.
//
// It does two things memoryStateStore does not, and each answers a half of a property no other
// route reaches:
//
//   - PutKeyPackage RETAINS the caller's slice headers rather than copying them. That is the only
//     route to "the two HPKE private halves are erased before NewKeyPackage returns": measured,
//     memoryStateStore's own entry is byte-identical under a correct body, under a body that
//     erases NEITHER and under one that erases only the init half, because it copies at call time
//     and nothing the engine does afterwards changes one octet of it. An erase is observable only
//     through an ALIAS of the array erased, and wherever the far side copies, the property must
//     build the alias or it is measuring a photograph.
//   - it records every call, so "and NOTHING ELSE" is a question that can be asked at all.
//
// IT IS NOT A STORE AND MUST NOT BECOME ONE. A production store that aliased a caller's array is
// exactly the defect the erase discipline forbids, and memoryStateStore must keep copying: the
// join's put-back is a statement about the store's OWN arrays.
//
// The methods are written out rather than promoted from an embedded mls.StateStore on purpose: a
// method added to that interface would arrive here already implemented, recording nothing, and
// quietly narrowing what every gate reading this can see.
type recordingAliasStore struct {
	inner     *memoryStateStore
	calls     []storeCall
	initAlias []byte
	encAlias  []byte
	// when set, TakeKeyPackage answers it instead of reading. StateStore.TakeKeyPackage returns
	// a BARE error with no declared not-found value, so a broken disk and a ref this store never
	// held are one answer to a caller matching on the type; this is how a gate drives the first
	// of the two.
	failTake error
}

var _ mls.StateStore = (*recordingAliasStore)(nil)

func newRecordingAliasStore() *recordingAliasStore {
	return &recordingAliasStore{inner: newMemoryStateStore()}
}

func (self *recordingAliasStore) recordStoreCall(method string, args ...[]byte) {
	copies := [][]byte{}
	for _, argument := range args {
		copies = append(copies, append([]byte(nil), argument...))
	}
	self.calls = append(self.calls, storeCall{method: method, args: copies})
}

// callsTo answers every call this store took of one method, in order.
func (self *recordingAliasStore) callsTo(method string) []storeCall {
	found := []storeCall{}
	for _, call := range self.calls {
		if call.method == method {
			found = append(found, call)
		}
	}
	return found
}

// methodsCalled answers the distinct method names this store was driven through, sorted.
func (self *recordingAliasStore) methodsCalled() []string {
	seen := map[string]bool{}
	for _, call := range self.calls {
		seen[call.method] = true
	}
	names := slices.Sorted(maps.Keys(seen))
	return names
}

func (self *recordingAliasStore) PutGroupState(groupId []byte, epoch uint64, state []byte) error {
	self.recordStoreCall("PutGroupState", groupId, state)
	return self.inner.PutGroupState(groupId, epoch, state)
}

func (self *recordingAliasStore) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	self.recordStoreCall("GetGroupState", groupId)
	return self.inner.GetGroupState(groupId, epoch)
}

func (self *recordingAliasStore) DeleteGroupStateBefore(groupId []byte, epoch uint64) error {
	self.recordStoreCall("DeleteGroupStateBefore", groupId)
	return self.inner.DeleteGroupStateBefore(groupId, epoch)
}

func (self *recordingAliasStore) PutPrivateKey(pub []byte, priv []byte) error {
	self.recordStoreCall("PutPrivateKey", pub, priv)
	return self.inner.PutPrivateKey(pub, priv)
}

func (self *recordingAliasStore) GetPrivateKey(pub []byte) ([]byte, error) {
	self.recordStoreCall("GetPrivateKey", pub)
	return self.inner.GetPrivateKey(pub)
}

func (self *recordingAliasStore) DeletePrivateKey(pub []byte) error {
	self.recordStoreCall("DeletePrivateKey", pub)
	return self.inner.DeletePrivateKey(pub)
}

func (self *recordingAliasStore) PutKeyPackage(ref []byte, kp []byte, initPriv []byte, encPriv []byte) error {
	self.recordStoreCall("PutKeyPackage", ref, kp, initPriv, encPriv)
	// THE SLICE HEADERS, not clones. This is the instrument.
	self.initAlias = initPriv
	self.encAlias = encPriv
	return self.inner.PutKeyPackage(ref, kp, initPriv, encPriv)
}

func (self *recordingAliasStore) TakeKeyPackage(ref []byte) ([]byte, []byte, []byte, error) {
	self.recordStoreCall("TakeKeyPackage", ref)
	if self.failTake != nil {
		return nil, nil, nil, self.failTake
	}
	return self.inner.TakeKeyPackage(ref)
}

// newRecordingEngine is one device whose engine writes into the instrument above.
func newRecordingEngine(t *testing.T) (*testEngine, *recordingAliasStore) {
	t.Helper()
	store := newRecordingAliasStore()
	engine, err := buildTestEngineOver(store, store.inner)
	if err != nil {
		t.Fatalf("build the engine this gate observes: %v", err)
	}
	return engine, store
}

// createGroup founds a group whose id is thirty two octets, which is the width a record header
// carries.
func (self *testEngine) createGroup(t *testing.T, name string) GroupHandle {
	t.Helper()
	handle, err := self.buildGroup(name)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	return handle
}

// buildGroup is createGroup without a *testing.T, for the probes.
func (self *testEngine) buildGroup(name string) (GroupHandle, error) {
	policy := &mls.GroupPolicyExtension{
		Roles: []mls.RoleEntry{{MemberId: self.identityPub, Role: mls.RoleOwner}},
	}
	if err := policy.Canonicalize(); err != nil {
		return nil, err
	}
	encoded, err := policy.Encode()
	if err != nil {
		return nil, err
	}
	return self.engine.CreateGroup(testGroupId(name), encoded.ExtensionData, self.leafKeys)
}

// buildProbeSession founds a fresh group and opens a session over it with the caller's secret as
// pq_secret, which is the one secret the constructor takes and does not derive.
//
// It exists for the one way ladder probes, which are handed a rung of the record key ladder and
// have to answer everything the member under test produces from it.
func buildProbeSession(pqSecret []byte) (*testSession, error) {
	engine, err := buildTestEngine()
	if err != nil {
		return nil, err
	}
	handle, err := engine.buildGroup("probe")
	if err != nil {
		return nil, err
	}
	reserver := newStreamIndexMemory()
	session, err := NewGroupSession(handle, pqSecret, nil, reserver, testClock(), testServerNonce())
	if err != nil {
		return nil, err
	}
	return &testSession{session: session, handle: handle, engine: engine, reserver: reserver}, nil
}

// testGroupId is one distinct thirty two octet group id per name.
func testGroupId(name string) []byte {
	groupId := make([]byte, 32)
	copy(groupId, name)
	return groupId
}

// The pq_secret every fixture supplies. NewPqSecret draws the real one; this is a constant so that a
// case comparing two sessions is comparing the two sessions rather than two draws.
//
// It is NOT a default and it is not reachable from production: the constructor refuses an empty
// pq_secret and takes no value of its own, so nothing in a shipped build can arrive at this
// value or at any other by accident.
func testPqSecret() []byte {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(0xA0 + i)
	}
	return secret
}

// testServerNonce is the submitting connection's nonce a fixture macs write_auth under.
func testServerNonce() []byte {
	return []byte("test-server-nonce")
}

// testClock is the injected clock: a fixed millisecond value, because this package has no
// timing sensitive test and must not gain one.
func testClock() func() int64 {
	return func() int64 { return 1_700_000_000_000 }
}

// testSession is one member's session over a real group, with the reserver it writes into.
type testSession struct {
	session  *GroupSession
	handle   GroupHandle
	engine   *testEngine
	reserver *streamIndexFake
}

// newTestSession founds a group and opens a session over it.
func newTestSession(t *testing.T, name string) *testSession {
	t.Helper()
	engine := newTestEngine(t)
	handle := engine.createGroup(t, name)
	reserver := newStreamIndexMemory()
	session, err := NewGroupSession(handle, testPqSecret(), nil, reserver, testClock(), testServerNonce())
	if err != nil {
		t.Fatalf("NewGroupSession: %v", err)
	}
	t.Cleanup(func() { session.Close() })
	return &testSession{session: session, handle: handle, engine: engine, reserver: reserver}
}

// trackOwn installs a receiver ratchet for this session's OWN durable ladder, which is what lets
// a case seal and open in one session.
func (self *testSession) trackOwn(t *testing.T) {
	t.Helper()
	if err := self.session.TrackSender(self.handle.OwnLeafIndex(), message.RetentionDurable, 0, 0); err != nil {
		t.Fatalf("TrackSender: %v", err)
	}
}
