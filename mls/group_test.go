// RFC 9420 section 11 group creation, held to the four steps rather than to the answer.
//
// WHAT THIS FILE IS BUILT AROUND. NewGroup is the one construction in this package with nothing on
// the other side of it: no peer sent these octets, no signature was made over them by anybody else,
// and no published vector covers a group id and an epoch secret somebody chose at random. Every
// field it writes is therefore a field whose only judge is a test in this file, and the two fields
// that matter most -- the founding leaf's HPKE key pair and the initial epoch_secret -- are the two
// a wrong value is completely invisible in. A constant epoch secret still expands into nine
// well formed secrets of the right length; a constant leaf key still seals, still opens, and still
// hashes into a perfectly good tree. Two entropy substitutions of exactly that shape passed 963
// green tests on p5.
//
// So the entropy test here does not assert over the LINES that draw. It records the draws the
// provider was asked for, and then finds each of them again in what the group PUBLISHES: the leaf
// key by re-deriving it, the epoch secret by rebuilding the whole key schedule over the group's own
// context and comparing the epoch authenticator. A draw that never reaches what the group published
// is a draw that was thrown away, and a group whose two founding secrets came out of ONE draw is
// caught by the two being found at the same index.
package mls

import (
	"bytes"
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/urnetwork/connect/mls/syntax"
)

// testStore is an in-memory StateStore for the lifecycle tests.
type testStore struct {
	states   map[string][]byte
	privs    map[string][]byte
	packages map[string][3][]byte
	deletes  []uint64
}

func newTestStore() *testStore {
	return &testStore{
		states:   map[string][]byte{},
		privs:    map[string][]byte{},
		packages: map[string][3][]byte{},
	}
}

// stateKey formats the epoch in decimal. string(rune(epoch)) would collapse every epoch in
// 0xD800-0xDFFF and everything above 0x10FFFF onto U+FFFD, and this fixture backs the past-epoch
// window assertions of task 19, where a silent collision reads as a correct deletion.
func stateKey(groupId []byte, epoch uint64) string {
	return string(groupId) + "/" + strconv.FormatUint(epoch, 10)
}

func (self *testStore) PutGroupState(groupId []byte, epoch uint64, state []byte) error {
	self.states[stateKey(groupId, epoch)] = bytes.Clone(state)
	return nil
}

func (self *testStore) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	state, held := self.states[stateKey(groupId, epoch)]
	if !held {
		return nil, errors.New("no state")
	}
	return state, nil
}

func (self *testStore) DeleteGroupStateBefore(groupId []byte, epoch uint64) error {
	self.deletes = append(self.deletes, epoch)
	for key := range self.states {
		for e := uint64(0); e < epoch; e += 1 {
			if key == stateKey(groupId, e) {
				delete(self.states, key)
			}
		}
	}
	return nil
}

func (self *testStore) PutPrivateKey(pub []byte, priv []byte) error {
	self.privs[string(pub)] = bytes.Clone(priv)
	return nil
}

func (self *testStore) GetPrivateKey(pub []byte) ([]byte, error) {
	priv, held := self.privs[string(pub)]
	if !held {
		return nil, errors.New("no key")
	}
	return priv, nil
}

func (self *testStore) DeletePrivateKey(pub []byte) error {
	delete(self.privs, string(pub))
	return nil
}

func (self *testStore) PutKeyPackage(ref []byte, kp []byte, initPriv []byte, encPriv []byte) error {
	self.packages[string(ref)] = [3][]byte{kp, initPriv, encPriv}
	return nil
}

func (self *testStore) TakeKeyPackage(ref []byte) ([]byte, []byte, []byte, error) {
	entry, held := self.packages[string(ref)]
	if !held {
		return nil, nil, nil, errors.New("no key package")
	}
	delete(self.packages, string(ref))
	return entry[0], entry[1], entry[2], nil
}

// testGroupConfig builds a v1-profile config for one member, who is the group's owner.
func testGroupConfig(t *testing.T, crypto CryptoProvider, owner *testMember, groupId string) *GroupConfig {
	t.Helper()
	policy := &GroupPolicyExtension{Roles: []RoleEntry{{MemberId: owner.IdentityPub, Role: RoleOwner}}}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	policyExt, err := policy.Encode()
	if err != nil {
		t.Fatalf("Encode policy: %v", err)
	}
	return &GroupConfig{
		Suite:      CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:    []byte(groupId),
		Extensions: []Extension{policyExt},
		RequiredCaps: RequiredCapabilities{
			ExtensionTypes: []ExtensionType{
				ExtensionTypeUrmessageGroupPolicy,
				ExtensionTypeUrmessageLeafKeys,
			},
		},
		Crypto:   crypto,
		Store:    newTestStore(),
		Profile:  defaultProfile(),
		LeafKeys: LeafKeysExtension{AlgId: AlgIdXwing, DeviceXwingPub: owner.XwingPub},
	}
}

func testNewGroup(t *testing.T, crypto CryptoProvider, owner *testMember, groupId string) *Group {
	t.Helper()
	cfg := testGroupConfig(t, crypto, owner, groupId)
	group, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	return group
}

// testGroupContextOf decodes the group's own published context, so that every assertion over it
// runs on the octets a peer would be handed rather than on the struct this package happens to hold.
func testGroupContextOf(t *testing.T, group *Group) *GroupContext {
	t.Helper()
	encoded, err := group.GroupContext()
	if err != nil {
		t.Fatalf("GroupContext: %v", err)
	}
	decoded := &GroupContext{}
	if err := syntax.Unmarshal(encoded, decoded); err != nil {
		t.Fatalf("unmarshal the published group context: %v", err)
	}
	return decoded
}

func TestNewGroupIsAOneMemberGroupAtEpochZero(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	if group.Epoch() != 0 {
		t.Fatalf("Epoch = %d, want 0", group.Epoch())
	}
	if group.OwnLeafIndex() != 0 {
		t.Fatalf("OwnLeafIndex = %d, want 0", group.OwnLeafIndex())
	}
	members := group.Members()
	if len(members) != 1 {
		t.Fatalf("Members = %d, want 1", len(members))
	}
	if !bytes.Equal(members[0].IdentityPub, owner.IdentityPub) {
		t.Fatal("the creator is not the single member")
	}
	if members[0].Role != RoleOwner {
		t.Fatalf("creator role = %v, want owner", members[0].Role)
	}
	if members[0].LeafKeys == nil || !bytes.Equal(members[0].LeafKeys.DeviceXwingPub, owner.XwingPub) {
		t.Fatal("the creator's leaf does not carry urmessage_leaf_keys")
	}
	at, found := group.MemberAt(0)
	if !found || !bytes.Equal(at.IdentityPub, owner.IdentityPub) {
		t.Fatalf("MemberAt(0) = %+v, %v", at, found)
	}
	if !bytes.Equal(group.GroupId(), []byte("group-1")) {
		t.Fatalf("GroupId = %q", group.GroupId())
	}
	if len(group.EpochAuthenticator()) != crypto.HashSize() {
		t.Fatalf("EpochAuthenticator length = %d, want %d",
			len(group.EpochAuthenticator()), crypto.HashSize())
	}
}

func TestNewGroupConfirmedTranscriptHashIsEmptyAtEpochZero(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	ctx := testGroupContextOf(t, group)
	// section 11: "Confirmed transcript hash: The zero-length octet string". KDF.Nh zero octets
	// and the hash of nothing are both well formed values of the wrong length, and both would
	// carry every assertion this file makes about the group except this one.
	if len(ctx.ConfirmedTranscriptHash) != 0 {
		t.Fatalf("ConfirmedTranscriptHash = %x, want the zero-length octet string",
			ctx.ConfirmedTranscriptHash)
	}
	if ctx.Epoch != 0 {
		t.Fatalf("group context epoch = %d, want 0", ctx.Epoch)
	}
	if ctx.Version != ProtocolVersionMls10 {
		t.Fatalf("group context version = %#04x", uint16(ctx.Version))
	}
	if ctx.CipherSuite != CipherSuiteX25519ChaCha20Sha256Ed25519 {
		t.Fatalf("group context ciphersuite = %#04x", uint16(ctx.CipherSuite))
	}
	if !bytes.Equal(ctx.GroupId, []byte("group-1")) {
		t.Fatalf("group context group id = %q", ctx.GroupId)
	}

	// the tree hash the context names is the hash of the tree the group publishes, taken over
	// the encoded tree rather than over the group's own field, so a context that named some
	// other tree's hash is visible from outside
	encodedTree, err := group.RatchetTree()
	if err != nil {
		t.Fatalf("RatchetTree: %v", err)
	}
	published, err := UnmarshalRatchetTree(encodedTree)
	if err != nil {
		t.Fatalf("UnmarshalRatchetTree: %v", err)
	}
	treeHash, err := published.TreeHash(crypto)
	if err != nil {
		t.Fatalf("TreeHash: %v", err)
	}
	if !bytes.Equal(ctx.TreeHash, treeHash) {
		t.Fatalf("group context tree hash = %x and the published tree hashes to %x",
			ctx.TreeHash, treeHash)
	}
}

// TestNewGroupFoldsTheEpochZeroConfirmationTagIntoTheInterimTranscriptHash is section 11's last
// step, and it is the one nothing outside this package can see.
//
// Section 11 ends with "Compute the updated interim_transcript_hash from the
// confirmed_transcript_hash and the confirmation_tag". A creator that skipped it holds the empty
// interim hash, derives a DIFFERENT confirmed hash for its first commit, and nothing notices --
// there is no second member at epoch 0 to disagree with, and a joiner at epoch 1 takes the confirmed
// hash out of the GroupInfo rather than recomputing it. The first thing that can see it is another
// implementation, which is to say the day this build is asked to interoperate.
//
// The expectation is rebuilt from the primitives rather than read off the group: the tag is a MAC
// over the empty octet string under this epoch's confirmation key, and the interim hash is
// Hash(confirmed || opaque(tag)). Both halves of the group's own transcript are asserted, because
// the confirmed half being empty is what makes the interim half the value it is.
func TestNewGroupFoldsTheEpochZeroConfirmationTagIntoTheInterimTranscriptHash(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	if len(group.transcript.Confirmed) != 0 {
		t.Fatalf("confirmed transcript hash = %x, want the zero-length octet string",
			group.transcript.Confirmed)
	}
	tag := crypto.Mac(group.schedule.Secrets().Confirmation, []byte{})
	want, err := InterimTranscriptHash(crypto, []byte{}, tag)
	if err != nil {
		t.Fatalf("InterimTranscriptHash: %v", err)
	}
	if len(want) == 0 {
		t.Fatal("the expectation this test compares against is empty")
	}
	if !bytes.Equal(group.transcript.Interim, want) {
		t.Fatalf("interim transcript hash = %x, want Hash(confirmed || opaque(confirmation_tag)) = %x",
			group.transcript.Interim, want)
	}
}

// TestNewGroupFoundingLeafIsKeyPackageSourcedAndValidates holds the founding leaf to section 7.3.
//
// The SOURCE is the field this is really about. Section 7.2 makes leaf_node_source select what the
// signature covers -- a key_package leaf carries a Lifetime and is bound to no group, an update or
// commit leaf carries none and is bound to a group id and a leaf index -- so a founding leaf built
// under one source and stamped with another is a leaf whose signature was made over a preimage it
// no longer describes. Nothing in the group's own arithmetic reads the field, so the tree hashes,
// the context encodes, and every epoch secret is the one it should be.
func TestNewGroupFoundingLeafIsKeyPackageSourcedAndValidates(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	leaf := group.OwnLeafNodeCopy()
	if leaf == nil {
		t.Fatal("the group holds no leaf at its own index")
	}
	// section 11's leaf is the creator's own key package leaf: it entered a tree nobody had
	// committed over, so there is no group id and no position for its signature to be bound to
	if leaf.LeafNodeSource != LeafNodeSourceKeyPackage {
		t.Fatalf("founding leaf source = %d, want key_package (%d)",
			leaf.LeafNodeSource, LeafNodeSourceKeyPackage)
	}
	ctx := testGroupContextOf(t, group)
	if err := leaf.Validate(&LeafValidationContext{
		Crypto:          crypto,
		Suite:           ctx.CipherSuite,
		GroupId:         ctx.GroupId,
		LeafIndex:       group.OwnLeafIndex(),
		ExpectedSource:  LeafNodeSourceKeyPackage,
		GroupExtensions: ctx.Extensions,
		NowMs:           uint64(time.Now().UnixMilli()),
	}); err != nil {
		t.Fatalf("the founding leaf does not pass section 7.3 validation: %v", err)
	}
	// and it is a COPY: a caller that scribbles on what it was handed must not reach the tree the
	// epoch's tree hash was taken over
	before, err := group.RatchetTree()
	if err != nil {
		t.Fatalf("RatchetTree: %v", err)
	}
	leaf.SignatureKey = bytes.Repeat([]byte{0x7f}, len(leaf.SignatureKey))
	after, err := group.RatchetTree()
	if err != nil {
		t.Fatalf("RatchetTree after the copy was written to: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("writing to the leaf OwnLeafNodeCopy handed back changed the group's own tree")
	}
}

// TestNewGroupBindsItsProposalCacheToEpochZeroOfThisGroup holds the binding the cache was given.
//
// The cache is bound at construction and only a VerifiedGroupContext can bind it. What this test
// can see is the PAIR the binding names; what says the pair came from a context this client
// verified rather than one NewGroup wrote down is
// TestEveryConstructionOfAVerifiedGroupContextIsClassifiedHere, which fails on the day this package
// grows a second way to build one. The two together are the rule: this one that the binding is
// right, that one that it was earned.
func TestNewGroupBindsItsProposalCacheToEpochZeroOfThisGroup(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	ctx := testGroupContextOf(t, group)
	if err := group.proposals.CheckEpoch(ctx); err != nil {
		t.Fatalf("the cache does not hold for the epoch its own group is in: %v", err)
	}
	later := ctx.Clone()
	later.Epoch = 1
	if err := group.proposals.CheckEpoch(later); err == nil {
		t.Fatal("the cache holds for epoch 1 of a group that is at epoch 0")
	}
	elsewhere := ctx.Clone()
	elsewhere.GroupId = []byte("group-2")
	if err := group.proposals.CheckEpoch(elsewhere); err == nil {
		t.Fatal("the cache holds for a group id it was not bound to")
	}
}

// entropyWitness records what a group creation asked its provider to draw, and what it derived a
// key pair from.
//
// It is a wrapper and not a stub: every answer is the real provider's, so the group it helps build
// is a real group whose secrets are real secrets. What it adds is the only thing an entropy gate
// can rest on -- knowing which values were drawn, so that each can be looked for in what the group
// went on to publish.
type entropyWitness struct {
	CryptoProvider
	draws [][]byte
	ikms  [][]byte
}

func (self *entropyWitness) Random(n int) []byte {
	drawn := self.CryptoProvider.Random(n)
	self.draws = append(self.draws, bytes.Clone(drawn))
	return drawn
}

func (self *entropyWitness) DeriveKeyPair(ikm []byte) (HpkePrivateKey, HpkePublicKey, error) {
	self.ikms = append(self.ikms, bytes.Clone(ikm))
	return self.CryptoProvider.DeriveKeyPair(ikm)
}

// drawIndexOf answers which recorded draw a value is, or -1 for a value that was never drawn.
func drawIndexOf(draws [][]byte, value []byte) int {
	for i, drawn := range draws {
		if bytes.Equal(drawn, value) {
			return i
		}
	}
	return -1
}

// TestNewGroupDrawsEachFoundingSecretFreshAndFromItsOwnDraw is the entropy gate, and it is written
// against what the group PUBLISHES rather than against the two lines that draw.
//
// Three defects it is built to see, each of which leaves every other test in this package green:
//
//  1. a draw replaced by a CONSTANT. The value the group published is then not one of the draws the
//     provider was asked for, so the search below finds nothing.
//  2. the two draws COLLAPSED into one, so that the founding leaf's key pair and the epoch secret
//     are the same 32 octets. Both are still fresh per group and both still change with the
//     entropy source, so a divergence test cannot see it; what sees it is the two being found at
//     the same INDEX.
//  3. a draw made and then THROWN AWAY. Every draw the provider was asked for has to be accounted
//     for by one of the two the group published, so a third draw is a failure here until somebody
//     says what it is for.
//
// The epoch secret is found by rebuilding the whole key schedule over the group's own published
// context and comparing the epoch authenticator, which is the only way to identify a value that no
// exported symbol of this package answers and that guardrail 6 says none ever may.
func TestNewGroupDrawsEachFoundingSecretFreshAndFromItsOwnDraw(t *testing.T) {
	base := testCrypto(t)
	owner := testIdentity(t, base, "owner")
	witness := &entropyWitness{CryptoProvider: base}
	cfg := testGroupConfig(t, witness, owner, "group-1")
	group, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	defer group.Close()

	if len(witness.draws) < 2 {
		t.Fatalf("group creation drew %d values; section 11 draws a leaf key pair and an epoch secret, which is two",
			len(witness.draws))
	}
	if len(witness.ikms) != 1 {
		t.Fatalf("group creation derived %d key pairs, want the one the founding leaf is keyed by",
			len(witness.ikms))
	}

	// the founding leaf's key pair, identified by re-deriving it from the draw it names
	leafDraw := drawIndexOf(witness.draws, witness.ikms[0])
	if leafDraw < 0 {
		t.Fatal("the founding leaf's key pair was derived from something this group creation never drew")
	}
	_, encPub, err := base.DeriveKeyPair(witness.draws[leafDraw])
	if err != nil {
		t.Fatalf("re-derive the founding key pair: %v", err)
	}
	leaf := group.OwnLeafNodeCopy()
	if leaf == nil {
		t.Fatal("the group holds no leaf at its own index")
	}
	if !bytes.Equal(leaf.EncryptionKey, encPub) {
		t.Fatalf("the founding leaf's encryption key is %x and draw %d derives %x",
			leaf.EncryptionKey, leafDraw, encPub)
	}

	// the epoch secret, identified by rebuilding this epoch's key schedule over the group's own
	// published context. No exported symbol answers an epoch secret and none ever may, so the
	// value is recognised by what it derives rather than read off the group.
	ctx := testGroupContextOf(t, group)
	authenticator := group.EpochAuthenticator()
	if len(authenticator) == 0 {
		t.Fatal("the group answered no epoch authenticator, so nothing below is being compared")
	}
	epochDraw := -1
	for i, drawn := range witness.draws {
		if len(drawn) != base.HashSize() {
			continue
		}
		rebuilt, scheduleErr := NewKeyScheduleFromEpochSecret(base, drawn, ctx)
		if scheduleErr != nil {
			t.Fatalf("rebuild the key schedule over draw %d: %v", i, scheduleErr)
		}
		if bytes.Equal(rebuilt.Secrets().EpochAuthenticator, authenticator) {
			if epochDraw >= 0 {
				t.Fatalf("draws %d and %d both rebuild this epoch, so one of them is not the epoch secret",
					epochDraw, i)
			}
			epochDraw = i
		}
		rebuilt.Zeroize()
	}
	if epochDraw < 0 {
		t.Fatal("no value this group creation drew rebuilds its key schedule; the epoch secret is not one of the draws")
	}

	// the two came out of DIFFERENT draws. Collapsed into one they are both still fresh per
	// group, so nothing that compares two groups can see it.
	if epochDraw == leafDraw {
		t.Fatalf("the founding leaf's key pair and the epoch secret are both draw %d; section 11 draws them separately",
			leafDraw)
	}
	// and nothing was drawn that the group did not publish
	for i := range witness.draws {
		if i != epochDraw && i != leafDraw {
			t.Errorf("draw %d is neither the founding leaf's key material nor the epoch secret; a draw nothing published is entropy this gate cannot follow",
				i)
		}
	}
}

func TestNewGroupTwoCreatorsDiverge(t *testing.T) {
	// epoch_secret is fresh random per RFC 9420 section 11, so two creators of the same group id
	// must not derive the same epoch authenticator -- and must not key the same founding leaf
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	first := testNewGroup(t, crypto, owner, "group-1")
	defer first.Close()
	second := testNewGroup(t, crypto, owner, "group-1")
	defer second.Close()

	if bytes.Equal(first.EpochAuthenticator(), second.EpochAuthenticator()) {
		t.Fatal("two group creations produced the same epoch authenticator; epoch_secret is not random")
	}
	firstLeaf, secondLeaf := first.OwnLeafNodeCopy(), second.OwnLeafNodeCopy()
	if firstLeaf == nil || secondLeaf == nil {
		t.Fatal("a group holds no leaf at its own index")
	}
	if bytes.Equal(firstLeaf.EncryptionKey, secondLeaf.EncryptionKey) {
		t.Fatal("two group creations keyed the same founding leaf; the leaf key pair is not random")
	}
}

func TestNewGroupRefusesNonV1Ciphersuite(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "group-1")
	// registered and implemented, refused at group creation by policy
	cfg.Suite = CipherSuiteX25519AesGcm128Sha256Ed25519
	_, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if !errors.Is(err, errProfileCiphersuite) {
		t.Fatalf("NewGroup error = %v, want errProfileCiphersuite", err)
	}
}

// TestNewGroupRefusesAProviderRunningAnotherSuite separates the profile's refusal from the
// wiring one. Both are about a ciphersuite and they are different faults: the profile refuses a
// suite this build will not create under, and this refuses a config and a provider that were
// wired together wrongly, over a suite the profile is perfectly happy with.
func TestNewGroupRefusesAProviderRunningAnotherSuite(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519AesGcm128Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider(0x0001): %v", err)
	}
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "group-1")
	_, err = NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if !errors.Is(err, errGroupConfigProviderSuite) {
		t.Fatalf("NewGroup error = %v, want errGroupConfigProviderSuite", err)
	}
	if errors.Is(err, errProfileCiphersuite) {
		t.Fatal("the wiring refusal also reads as the profile refusal, so a caller cannot tell the two apart")
	}
}

func TestNewGroupRefusesGroupWithoutPolicy(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "group-1")
	cfg.Extensions = nil
	_, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if !errors.Is(err, ErrNoGroupPolicy) {
		t.Fatalf("NewGroup error = %v, want ErrNoGroupPolicy", err)
	}
}

func TestNewGroupRefusesAConfigWithNoStore(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "group-1")
	cfg.Store = nil
	_, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if !errors.Is(err, errNilStateStore) {
		t.Fatalf("NewGroup error = %v, want errNilStateStore", err)
	}
}

func TestEpochSecretAccessorIsClosed(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	senderData, err := group.EpochSecret(EpochSecretSenderData)
	if err != nil {
		t.Fatalf("EpochSecret(sender_data): %v", err)
	}
	encryption, err := group.EpochSecret(EpochSecretEncryption)
	if err != nil {
		t.Fatalf("EpochSecret(encryption): %v", err)
	}
	if len(senderData) != crypto.HashSize() || len(encryption) != crypto.HashSize() {
		t.Fatalf("sender_data is %d octets and encryption is %d, want %d",
			len(senderData), len(encryption), crypto.HashSize())
	}
	if bytes.Equal(senderData, encryption) {
		t.Fatal("sender_data_secret and encryption_secret must be independent derivations")
	}
	if _, err := group.EpochSecret(EpochSecretName(9)); err == nil {
		t.Fatal("EpochSecret accepted a name outside the closed enum")
	}
	if _, err := group.EpochSecret(EpochSecretName(0)); err == nil {
		t.Fatal("EpochSecret accepted the zero value, which is a caller that named nothing")
	}
}

// TestAClosedGroupRefusesItsSecretsRatherThanAnsweringZeros is what makes Close safe to defer.
//
// Zeroize leaves KDF.Nh zero octets behind rather than a short slice, so an accessor that went on
// reading the schedule after a close would answer a secret of exactly the right length that every
// closed group in the process agrees on.
func TestAClosedGroupRefusesItsSecretsRatherThanAnsweringZeros(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")

	if err := group.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// idempotent, because a deferred close beside an explicit one is not a mistake
	if err := group.Close(); err != nil {
		t.Fatalf("Close twice: %v", err)
	}
	if secret := group.EpochAuthenticator(); secret != nil {
		t.Fatalf("a closed group answered an epoch authenticator of %x", secret)
	}
	if _, err := group.EpochSecret(EpochSecretEncryption); !errors.Is(err, errGroupClosed) {
		t.Fatalf("EpochSecret on a closed group = %v, want errGroupClosed", err)
	}
	if _, err := group.Export("label", nil, 32); !errors.Is(err, errGroupClosed) {
		t.Fatalf("Export on a closed group = %v, want errGroupClosed", err)
	}
	// and the state that is not secret is still readable, which is what a closed group is for
	if group.Epoch() != 0 || !bytes.Equal(group.GroupId(), []byte("group-1")) {
		t.Fatal("a closed group forgot which group it was")
	}
}

func TestGroupExportAnswersTheKeyScheduleExporter(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	exported, err := group.Export("urmessage exporter", []byte("context"), 32)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	want, err := group.schedule.Export("urmessage exporter", []byte("context"), 32)
	if err != nil {
		t.Fatalf("KeySchedule.Export: %v", err)
	}
	if !bytes.Equal(exported, want) {
		t.Fatalf("Export = %x, want %x", exported, want)
	}
	// a different label is a different secret, so the exporter is reading its arguments
	other, err := group.Export("another label", []byte("context"), 32)
	if err != nil {
		t.Fatalf("Export under another label: %v", err)
	}
	if bytes.Equal(exported, other) {
		t.Fatal("two labels exported the same secret")
	}
}

func TestGroupStateIsPersistedAtCreation(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "group-1")
	store, isTestStore := cfg.Store.(*testStore)
	if !isTestStore {
		t.Fatalf("the fixture's store is a %T", cfg.Store)
	}
	group, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	defer group.Close()

	blob, err := store.GetGroupState([]byte("group-1"), 0)
	if err != nil {
		t.Fatalf("epoch 0 state was not persisted: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("the persisted epoch 0 state is empty")
	}
	// nothing is written at any other epoch, which is what makes task 19's past-epoch window a
	// window over something
	if _, err := store.GetGroupState([]byte("group-1"), 1); err == nil {
		t.Fatal("group creation wrote state at epoch 1")
	}
}

// TestTheV1ProfileClassifiesEveryRegisteredCiphersuiteForCreation holds the creation table to the
// suite registry in both directions, and then holds the door to the table.
//
// The registry is Suites(), which is read off registeredSuiteParams rather than written down here:
// a suite added to this build with no row is a code point the door would answer "not registered"
// about, which is a sentence about a registration that is right there.
func TestTheV1ProfileClassifiesEveryRegisteredCiphersuiteForCreation(t *testing.T) {
	registered := Suites()
	if len(registered) == 0 {
		t.Fatal("this build registers no ciphersuite, so this gate read nothing")
	}
	admitted, refused := 0, 0
	for _, suite := range registered {
		refusal, classified := createSuiteProfile[suite]
		if !classified {
			t.Errorf("suite.go registers %#04x and createSuiteProfile has no row for it",
				uint16(suite))
			continue
		}
		if refusal == nil {
			admitted += 1
		} else {
			refused += 1
		}
	}
	for suite := range createSuiteProfile {
		if !slices.Contains(registered, suite) {
			t.Errorf("createSuiteProfile holds a row for %#04x and this build registers no such suite",
				uint16(suite))
		}
	}
	// both halves non-empty, or the table is satisfied by one answer. A profile that refused
	// only suites this build does not implement would be stating nothing at all.
	if admitted == 0 || refused == 0 {
		t.Fatalf("the creation profile admits %d suites and refuses %d; a table whose answer is the same for every member states nothing",
			admitted, refused)
	}
	// and the door answers what the table holds, so the two cannot drift
	active := defaultProfile()
	for _, suite := range registered {
		err := active.checkCiphersuiteForCreate(suite)
		switch want := createSuiteProfile[suite]; {
		case want == nil && err != nil:
			t.Errorf("the table admits %#04x for creation and the door answered %v", uint16(suite), err)
		case want != nil && !errors.Is(err, want):
			t.Errorf("the table refuses %#04x with %v and the door answered %v", uint16(suite), want, err)
		}
	}
	// an unregistered code point is a different sentence: there is no narrowing to name
	if err := active.checkCiphersuiteForCreate(CipherSuite(0xBEEF)); !errors.Is(err, ErrUnknownCipherSuite) {
		t.Errorf("checkCiphersuiteForCreate(0xBEEF) = %v, want ErrUnknownCipherSuite", err)
	}
	t.Logf("%d registered suites, %d admitted for creation and %d refused",
		admitted+refused, admitted, refused)
}

// TestNewGroupRefusesANilConfig holds the one argument that carries the whole group.
//
// It answers its own value rather than ErrNilCryptoProvider, because a caller that passed no config
// has not passed a config with no provider: the two are different mistakes made in different lines
// and repaired in different places.
func TestNewGroupRefusesANilConfig(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	_, err := NewGroup(nil, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if !errors.Is(err, errNilGroupConfig) {
		t.Fatalf("NewGroup(nil) = %v, want errNilGroupConfig", err)
	}
	if errors.Is(err, ErrNilCryptoProvider) {
		t.Fatal("a nil config reads as a nil provider, so a caller cannot tell which it forgot")
	}
}

func TestNewGroupRefusesAConfigWithNoProvider(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "group-1")
	cfg.Crypto = nil
	_, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if !errors.Is(err, ErrNilCryptoProvider) {
		t.Fatalf("NewGroup over a config with no provider = %v, want ErrNilCryptoProvider", err)
	}
}

// truncatingMacProvider is a provider whose MAC answers one octet short of a tag.
//
// It exists for one door and is not a hypothetical shape: (*KeySchedule).ConfirmationTag answers
// NIL for an epoch whose confirmation_key has been erased, and a creation path that folded a nil or
// short tag into the interim transcript hash would found a group whose transcript nobody else can
// reproduce -- with no error anywhere, because InterimTranscriptHash length-prefixes whatever it is
// handed and hashes it happily.
type truncatingMacProvider struct {
	CryptoProvider
}

func (self *truncatingMacProvider) Mac(key []byte, data []byte) []byte {
	full := self.CryptoProvider.Mac(key, data)
	return full[:len(full)-1]
}

func TestNewGroupRefusesAConfirmationTagOfTheWrongWidth(t *testing.T) {
	base := testCrypto(t)
	owner := testIdentity(t, base, "owner")
	cfg := testGroupConfig(t, &truncatingMacProvider{CryptoProvider: base}, owner, "group-1")
	_, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if !errors.Is(err, errCreationConfirmationTag) {
		t.Fatalf("NewGroup over a provider whose MAC is a byte short = %v, want errCreationConfirmationTag", err)
	}
}

// TestNewGroupCarriesTheExtensionsItsCreatorChose holds the other half of what section 11 lets the
// creator decide, and it is the half nothing else in this file reads.
//
// The group context's extensions vector is covered by the confirmed transcript hash and by every
// epoch secret expanded over it, so a creator that dropped required_capabilities founds a group
// whose members are held to nothing and whose context still hashes, still encodes and still derives
// a perfectly good key schedule. Section 11.1 is what the vector is for: it is the group's statement
// of what every member must support, and a group that never made it cannot be told from one whose
// members all happen to support the right things.
func TestNewGroupCarriesTheExtensionsItsCreatorChose(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "group-1")
	group, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	defer group.Close()

	ctx := testGroupContextOf(t, group)
	body, carried, err := FindExtension(ctx.Extensions, ExtensionTypeRequiredCapabilities)
	if err != nil {
		t.Fatalf("FindExtension(required_capabilities): %v", err)
	}
	if !carried {
		t.Fatal("the group context carries no required_capabilities, and the config asked for two extension types")
	}
	required := &RequiredCapabilities{}
	if err := syntax.Unmarshal(body, required); err != nil {
		t.Fatalf("unmarshal required_capabilities: %v", err)
	}
	if !slices.Equal(required.ExtensionTypes, cfg.RequiredCaps.ExtensionTypes) {
		t.Fatalf("required extension types = %v, want %v",
			required.ExtensionTypes, cfg.RequiredCaps.ExtensionTypes)
	}
	// the policy the creator chose is there too, and it is the same one GroupPolicy answers
	policy, err := group.GroupPolicy()
	if err != nil {
		t.Fatalf("GroupPolicy: %v", err)
	}
	role, named := policy.RoleOf(owner.IdentityPub)
	if !named || role != RoleOwner {
		t.Fatalf("the group policy names the creator as %v (named=%v), want owner", role, named)
	}
	// and every leaf in the group supports what the group requires, which is section 11.1's own
	// rule and the reason a creator may not require what it cannot itself do
	leaf := group.OwnLeafNodeCopy()
	if leaf == nil {
		t.Fatal("the group holds no leaf at its own index")
	}
	if err := leaf.Capabilities.Supports(required); err != nil {
		t.Fatalf("the founding leaf does not support the capabilities its own group requires: %v", err)
	}
}
