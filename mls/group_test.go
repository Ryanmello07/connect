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
	"fmt"
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

// ---------------------------------------------------------------------------
// RFC 9420 section 12.1: proposal generation
// ---------------------------------------------------------------------------

// WHAT THE TESTS BELOW ARE BUILT AROUND. Proposal generation is the SENDING side of everything
// validate_proposals.go, validate_commit.go and the proposal cache judge on the receiving side, so
// the strongest thing that can be said about it is not that its output parses -- it is that this
// package's own doors ACCEPT what this package produced. A generator that emits a proposal its own
// validator refuses is a defect nothing downstream would report until a peer refused a commit, and
// it is a defect this package can detect in one call. That is
// TestEveryProposalThisGroupGeneratesIsAcceptedByItsOwnValidationDoors, and it is the reason the
// fixtures here go to the trouble of giving the group a second leaf.
//
// The second entropy gate is here for the reason the creation one is, one file section up: an
// Update exists to publish a FRESH encryption key and nothing else, and a constant in place of that
// draw still derives, still seals, still validates and still round trips. So the key is found again
// in the draws the provider was asked for rather than asserted over the line that made it.

// pendingProposalsForTest exposes this epoch's proposal cache to tests in this package.
//
// Declared here and not in group.go, which is framing_group_seams_test.go's precedent one file
// over: it is scaffolding no production caller has, and a helper spelled ForTest in the shipped
// source is a method every later reader has to work out is not part of the API.
//
// It reads through Cached rather than off the cache's map, because Pending answers REFERENCES and
// the entry behind one belongs to this epoch only if the cache is still bound to it -- which is the
// question Cached asks and a map lookup does not.
func (self *Group) pendingProposalsForTest() []CachedProposal {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	out := []CachedProposal{}
	for _, entry := range self.proposals.Pending(self.context) {
		if cached, held := self.proposals.Cached(self.context, entry.Reference); held {
			out = append(out, cached)
		}
	}
	return out
}

// testGroupWithASecondLeaf splices one more member into a founded group's ratchet tree and rebuilds
// its secret tree at the new width.
//
// IT EDITS THE GROUP'S OWN STATE ON PURPOSE and it is not a stand-in for task 13's commit: the
// group context still names the one-leaf tree hash, and this is not a group two clients could
// agree on. What it makes real is exactly the two facts the tests below cannot do without.
//
// The first is that a leaf OTHER than our own is occupied, so ProposeRemove has a member to name,
// ValSem108 has one to find and ValSem111 has a committer that is not the updating sender. Every
// one of those rules is stated over a second member, and a one-member group cannot observe any of
// them.
//
// The second is that the SECRET TREE carries a ratchet at that leaf. Without it a proposal
// misattributed to leaf 1 fails inside the key source with "leaf out of range", so the sender
// attribution test would report a failure it never actually observed -- the message would not
// exist to be attributed. With it, a misattributed proposal is a well formed message, which is the
// input that test's name claims to judge.
func testGroupWithASecondLeaf(t *testing.T, crypto CryptoProvider, group *Group, m *testMember) LeafIndex {
	t.Helper()
	leaf, _ := testLeafNode(t, crypto, m)
	at, err := group.tree.AddLeaf(leaf)
	if err != nil {
		t.Fatalf("add %s's leaf to the group's tree: %v", m.Name, err)
	}
	if at == group.OwnLeafIndex() {
		t.Fatalf("%s landed at the group's own leaf %d, so this fixture added nothing", m.Name, at)
	}
	secretTree, err := NewSecretTree(crypto, group.tree.LeafWidth(), group.schedule.Secrets().Encryption)
	if err != nil {
		t.Fatalf("rebuild the secret tree at %d leaves: %v", group.tree.LeafWidth(), err)
	}
	group.secretTree.Zeroize()
	group.secretTree = secretTree
	return at
}

// testOpenOwnProposal opens a message this group sealed, the way a PEER would.
//
// A RECEIVER'S OWN RATCHET AND NOT THE SENDER'S, which is the whole reason this is not two lines.
// NextMessageKey CONSUMES, so the generation a proposal was sealed under is already spent in the
// group's own secret tree; a peer derives the same ratchet from the same encryption secret, and
// rebuilding one here is what lets these tests read what was actually sent rather than what the
// sender happens to still hold.
//
// The signature key is resolved out of the group's own tree at the leaf the SENDER DATA names, so
// a message attributed to a leaf its signer does not occupy fails the signature check exactly as it
// would at a peer.
func testOpenOwnProposal(t *testing.T, crypto CryptoProvider, group *Group, encoded []byte) *AuthenticatedContent {
	t.Helper()
	parsed, err := ParseMLSMessage(encoded)
	if err != nil {
		t.Fatalf("ParseMLSMessage: %v", err)
	}
	if parsed.WireFormat != WireFormatPrivateMessage {
		t.Fatalf("wire format = %#x, want PrivateMessage: A-ASSUME-4 puts handshake traffic in PrivateMessage",
			parsed.WireFormat)
	}
	if parsed.PrivateMessage == nil {
		t.Fatal("the message names PrivateMessage and carries no private message arm")
	}
	receiver, err := NewSecretTree(crypto, group.tree.LeafWidth(), group.schedule.Secrets().Encryption)
	if err != nil {
		t.Fatalf("build the receiver's secret tree: %v", err)
	}
	groupContext, err := group.GroupContext()
	if err != nil {
		t.Fatalf("GroupContext: %v", err)
	}
	resolve := func(sender Sender) (SignaturePublicKey, error) {
		leaf := group.tree.Leaf(sender.LeafIndex)
		if leaf == nil {
			return nil, fmt.Errorf("no leaf at %d", sender.LeafIndex)
		}
		return leaf.SignatureKey, nil
	}
	opened, err := OpenPrivateMessage(crypto, receiver, group.schedule.Secrets().SenderData,
		parsed.PrivateMessage, resolve, groupContext)
	if err != nil {
		t.Fatalf("OpenPrivateMessage: %v", err)
	}
	return opened
}

// proposalGeneratorRow is one kind of proposal this group can generate, plus the leaf a commit
// carrying it would be made by.
//
// THE COMMITTER IS PART OF THE ROW because it is part of the rule. RFC 9420 section 12.2 refuses a
// commit that covers its own sender's Update -- the committer's leaf is reset by the UpdatePath
// instead -- so an update is judged under ANOTHER member's commit, and a row that named the
// updating leaf would be asserting that this package accepts something it is required to refuse.
type proposalGeneratorRow struct {
	name      string
	kind      ProposalType
	committer LeafIndex
	propose   func() ([]byte, error)
}

// proposalGeneratorRows is every proposal kind (*Group) can generate, which is the accepted set of
// the v1 profile's own proposal table.
//
// The rows are checked against that table in both directions by the sweep that uses them, so a
// fifth accepted type with no generator and a generator for a type the profile no longer accepts
// both fail rather than going unnoticed.
func proposalGeneratorRows(t *testing.T, crypto CryptoProvider, group *Group,
	joinerKeyPackage []byte, other LeafIndex, extensions []Extension) []proposalGeneratorRow {

	t.Helper()
	own := group.OwnLeafIndex()
	return []proposalGeneratorRow{
		{name: "add", kind: ProposalTypeAdd, committer: own, propose: func() ([]byte, error) {
			return group.ProposeAdd(joinerKeyPackage)
		}},
		{name: "remove", kind: ProposalTypeRemove, committer: own, propose: func() ([]byte, error) {
			return group.ProposeRemove(other)
		}},
		{name: "group_context_extensions", kind: ProposalTypeGroupContextExtensions, committer: own,
			propose: func() ([]byte, error) {
				return group.ProposeGroupContextExtensions(extensions)
			}},
		{name: "update", kind: ProposalTypeUpdate, committer: other, propose: func() ([]byte, error) {
			return group.ProposeUpdate()
		}},
	}
}

// testProposalGenerationFixture founds a group with a second member, mints a joiner's key package
// and answers everything the two sweeps below drive.
func testProposalGenerationFixture(t *testing.T) (CryptoProvider, *Group, []proposalGeneratorRow) {
	t.Helper()
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	t.Cleanup(func() { group.Close() })
	other := testGroupWithASecondLeaf(t, crypto, group, testIdentity(t, crypto, "bob"))

	joiner := testIdentity(t, crypto, "carol")
	kp, _, _ := testKeyPackage(t, crypto, joiner)
	encoded, err := syntax.Marshal(kp)
	if err != nil {
		t.Fatalf("marshal the joiner's key package: %v", err)
	}
	// the group's OWN published extensions, re-proposed. A group context extensions proposal
	// replaces the list wholesale, so this is the smallest one a real caller could send: a list
	// that still carries the policy the group runs under.
	published := testGroupContextOf(t, group).Extensions
	rows := proposalGeneratorRows(t, crypto, group, encoded, other, published)

	// the rows ARE the accepted set of the profile's proposal table, in both directions. A fifth
	// accepted type with no generator would be a proposal kind these sweeps never judged, and a
	// generator for a type the profile no longer accepts would be a row that outlived its rule.
	generated := map[ProposalType]bool{}
	for _, row := range rows {
		if generated[row.kind] {
			t.Fatalf("two rows generate %s", proposalTypeName(row.kind))
		}
		generated[row.kind] = true
	}
	for kind, refusal := range proposalTypeProfile {
		if refusal == nil && !generated[kind] {
			t.Errorf("the v1 profile accepts %s and no row generates one, so nothing here judges it",
				proposalTypeName(kind))
		}
		if refusal != nil && generated[kind] {
			t.Errorf("a row generates %s, which the v1 profile refuses", proposalTypeName(kind))
		}
	}
	return crypto, group, rows
}

// TestEveryProposalThisGroupGeneratesIsAcceptedByItsOwnValidationDoors is the gate this task's
// whole design rests on.
//
// The receive path of this package holds ValSem101-113, section 12.1.2's two rules on an Update's
// leaf, and section 12.2's three list rules. Every one of them is a rule the SENDING side must not
// violate, and a generator that emits a proposal its own validator refuses is a defect that shows
// up as a peer refusing a commit, several steps and one epoch away from the line that caused it.
//
// It is written over ValidateProposalList and not over an assertion about what the generator does,
// because the whole point is that the two are independent: the generator gets to be right for its
// own reasons and the validator gets to judge it for the RFC's.
//
// A ONE ENTRY LIST PER ROW, deliberately. This is a claim about each proposal on its own; the
// cross-proposal rules -- two adds publishing one key, an update and a remove on one leaf -- are
// about a LIST somebody assembled and are validate_proposals.go's own tests to make.
func TestEveryProposalThisGroupGeneratesIsAcceptedByItsOwnValidationDoors(t *testing.T) {
	crypto, group, rows := testProposalGenerationFixture(t)
	context := testGroupContextOf(t, group)
	for _, row := range rows {
		before := len(group.pendingProposalsForTest())
		if _, err := row.propose(); err != nil {
			t.Fatalf("%s: %v", row.name, err)
		}
		cached := group.pendingProposalsForTest()
		if len(cached) != before+1 {
			t.Fatalf("%s: the cache held %d entries before and %d after, so this row has no entry to judge",
				row.name, before, len(cached))
		}
		one := cached[len(cached)-1]
		if one.Proposal.ProposalType != row.kind {
			t.Fatalf("%s: the cache's newest entry is a %s", row.name,
				proposalTypeName(one.Proposal.ProposalType))
		}
		in := &ProposalValidationInput{
			Crypto:    crypto,
			Tree:      group.tree,
			Context:   context,
			Committer: row.committer,
			List:      NewProposalList([]CachedProposal{one}),
			Now:       time.Now(),
		}
		if err := ValidateProposalList(in); err != nil {
			t.Errorf("%s: this group generated a proposal its own ValidateProposalList refuses: %v",
				row.name, err)
		}
		// AND, FOR THE PROPOSAL THAT INSTALLS AN EXTENSION SET, THE COMMIT DOOR'S OWN READ OF IT.
		// ValSem209 is not one of section 12.2's list rules and ValidateProposalList does not run
		// it, so a generator held to the list rules alone is held to strictly less than a receiver
		// applies. Measured: without this the generator published a set carrying
		// required_capabilities twice -- which every list rule accepts, because none of them looks
		// that body up, and which ValSem209 refuses because it reads it through the lookup.
		if row.kind != ProposalTypeGroupContextExtensions {
			continue
		}
		commitIn := testCommitInput(t, crypto, group.tree, in.List, &Commit{})
		commitIn.Context = context
		commitIn.Committer = row.committer
		commitIn.Own = group.OwnLeafIndex()
		// erratum 8815 runs at the commit door and asks whether every reference the commit names
		// was previously received; the entry this row just cached is where that answer comes from
		commitIn.Pending = group.proposals
		commitIn.Now = time.Now()
		if err := ValSem209GroupExtensionsSupported(commitIn); err != nil {
			t.Errorf("%s: this group generated an extension set its own ValSem209 refuses: %v",
				row.name, err)
		}
	}
}

// TestEveryProposalThisGroupGeneratesNamesItsOwnLeafAsSender reads the sender out of what was
// actually SENT.
//
// The sender is the one field of a proposal nothing else can supply. It travels in the encrypted
// sender data, so a peer learns it from the message and from nowhere else; ValSem111 compares it
// against the committer, section 12.1.2 rebuilds the update leaf's own preimage from it, and the
// cache keys its per sender ceilings on it. A generator that attributed its proposals to another
// leaf would produce messages that decrypt, parse and carry a perfectly good proposal -- and every
// rule stated over a sender would then be a rule about somebody else.
//
// Both readings are taken and they are different claims: the CACHE's attribution is what this
// client's own commit path will use, and the MESSAGE's is what every peer will use. A generator
// that got one right and the other wrong would be a group whose commit says one thing and whose
// wire says another.
func TestEveryProposalThisGroupGeneratesNamesItsOwnLeafAsSender(t *testing.T) {
	crypto, group, rows := testProposalGenerationFixture(t)
	own := group.OwnLeafIndex()
	for _, row := range rows {
		message, err := row.propose()
		if err != nil {
			t.Fatalf("%s: %v", row.name, err)
		}
		cached := group.pendingProposalsForTest()
		one := cached[len(cached)-1]
		if one.Sender != own {
			t.Errorf("%s: the cache attributed this proposal to leaf %d and this client is leaf %d",
				row.name, one.Sender, own)
		}
		opened := testOpenOwnProposal(t, crypto, group, message)
		if opened.Content.Sender.SenderType != SenderTypeMember {
			t.Errorf("%s: sender type = %d, want member", row.name, opened.Content.Sender.SenderType)
		}
		if opened.Content.Sender.LeafIndex != own {
			t.Errorf("%s: the message names leaf %d as its sender and this client is leaf %d",
				row.name, opened.Content.Sender.LeafIndex, own)
		}
		if !bytes.Equal(opened.Content.GroupId, group.GroupId()) {
			t.Errorf("%s: the message names group %x and this group is %x",
				row.name, opened.Content.GroupId, group.GroupId())
		}
		if opened.Content.Epoch != group.Epoch() {
			t.Errorf("%s: the message names epoch %d and this group is at %d",
				row.name, opened.Content.Epoch, group.Epoch())
		}
		if opened.Content.ContentType != ContentTypeProposal {
			t.Errorf("%s: content type = %d, want proposal", row.name, opened.Content.ContentType)
		}
		if opened.Content.Proposal == nil {
			t.Fatalf("%s: the message carries no proposal arm", row.name)
		}
		if opened.Content.Proposal.ProposalType != row.kind {
			t.Errorf("%s: the message carries a %s", row.name,
				proposalTypeName(opened.Content.Proposal.ProposalType))
		}
	}
}

// TestProposingLeavesTheEpochAndTheOwnLeafAlone is the "a proposal is a request and not a change"
// half.
//
// The own leaf is the reading that can fail on its own. An implementation that applied its own
// Update as it proposed it would hold a leaf no peer has seen, publish a tree hash nothing agrees
// with from the next commit onward, and answer every structural question correctly in between --
// and the epoch, which is the obvious thing to check, would still be right.
func TestProposingLeavesTheEpochAndTheOwnLeafAlone(t *testing.T) {
	_, group, rows := testProposalGenerationFixture(t)
	epoch := group.Epoch()
	before := group.OwnLeafNodeCopy()
	if before == nil {
		t.Fatal("OwnLeafNodeCopy returned nil, so this test compares nothing")
	}
	members := len(group.Members())
	for _, row := range rows {
		if _, err := row.propose(); err != nil {
			t.Fatalf("%s: %v", row.name, err)
		}
		if group.Epoch() != epoch {
			t.Fatalf("%s: the epoch went from %d to %d; proposing is not an epoch change",
				row.name, epoch, group.Epoch())
		}
		after := group.OwnLeafNodeCopy()
		if after == nil {
			t.Fatalf("%s: the group holds no leaf at its own index afterwards", row.name)
		}
		if !bytes.Equal(after.EncryptionKey, before.EncryptionKey) {
			t.Fatalf("%s: this client's own leaf now publishes %x and published %x before; a proposal is not applied by the client that made it",
				row.name, after.EncryptionKey, before.EncryptionKey)
		}
		if got := len(group.Members()); got != members {
			t.Fatalf("%s: the group went from %d members to %d", row.name, members, got)
		}
	}
}

// TestNewGroupFoundsAContextItsOwnProposalDoorsAccept is task 12's own claim turned on task 11,
// which is where the same class turned out to be standing.
//
// The claim these two tests share is that a list this build EMITS is one its own readers accept.
// For a proposal that is ValidateProposalList; for a group context it is the same door, because
// every rule of section 12.2 that reads an extension reads the GROUP'S context through it. The
// creation path assembles that context out of two sources -- the caller's extensions and a
// required_capabilities entry it encodes and prepends itself -- and nothing joined them: a config
// that set RequiredCaps AND supplied its own encoded entry founded a group carrying the type twice,
// which FindExtension refuses for every reader afterwards. The group was created, signed and
// persisted, and then every proposal list anyone built against it was refused with a message about
// an extensions vector.
//
// It is written over the DOOR and not over a count of entries, for the reason the proposal rows
// are: a count is this test's own opinion about what a repeat looks like, and the door is what the
// rest of the package will actually do with the context.
func TestNewGroupFoundsAContextItsOwnProposalDoorsAccept(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()
	in := &ProposalValidationInput{
		Crypto:  crypto,
		Tree:    group.tree,
		Context: testGroupContextOf(t, group),
		List:    NewProposalList([]CachedProposal{}),
		Now:     time.Now(),
	}
	if err := ValidateProposalList(in); err != nil {
		t.Fatalf("this group's own published context is one its own proposal door refuses: %v", err)
	}
}

// TestNewGroupRefusesAConfigThatWouldCarryRequiredCapabilitiesTwice is the refusal half, over the
// one input that reaches it: the entry the creation path adds is the only one no earlier check
// joined against the caller's own list.
func TestNewGroupRefusesAConfigThatWouldCarryRequiredCapabilitiesTwice(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "group-1")
	if len(cfg.RequiredCaps.ExtensionTypes) == 0 {
		t.Fatal("this fixture no longer sets RequiredCaps, so nothing is prepended and this test drives nothing")
	}
	supplied, err := encodeRequiredCapabilities(&RequiredCapabilities{
		ExtensionTypes: []ExtensionType{ExtensionTypeUrmessageGroupPolicy},
	})
	if err != nil {
		t.Fatalf("encode the caller's own required_capabilities: %v", err)
	}
	cfg.Extensions = append(cfg.Extensions, supplied)
	group, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if err == nil {
		group.Close()
		t.Fatal("a config that both sets RequiredCaps and supplies its own required_capabilities founded a group; its context carries the type twice and every later reader refuses it")
	}
	if !errors.Is(err, ErrMalformedExtension) {
		t.Fatalf("NewGroup error = %v, want ErrMalformedExtension; the refusal is the lookup's", err)
	}
}

// TestProposeAddProducesACacheableProposal is the plan's own row, kept because it is the one that
// reads the wire format.
func TestProposeAddProducesACacheableProposal(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	bob := testIdentity(t, crypto, "bob")
	kp, _, _ := testKeyPackage(t, crypto, bob)
	encoded, err := syntax.Marshal(kp)
	if err != nil {
		t.Fatalf("marshal key package: %v", err)
	}
	message, err := group.ProposeAdd(encoded)
	if err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}
	if len(message) == 0 {
		t.Fatal("ProposeAdd returned no message")
	}
	parsed, err := ParseMLSMessage(message)
	if err != nil {
		t.Fatalf("ParseMLSMessage: %v", err)
	}
	if parsed.WireFormat != WireFormatPrivateMessage {
		t.Fatalf("wire format = %#x, want PrivateMessage: A-ASSUME-4 puts handshake traffic in PrivateMessage",
			parsed.WireFormat)
	}
	if group.Epoch() != 0 {
		t.Fatal("proposing must not advance the epoch")
	}
	cached := group.pendingProposalsForTest()
	if len(cached) != 1 {
		t.Fatalf("the proposal was not cached: %d entries", len(cached))
	}
	if cached[0].Proposal.Add == nil {
		t.Fatal("the cached entry carries no add arm")
	}
	// the KEY PACKAGE the caller handed over and not some other one, read off the cache's own
	// copy: the entry is what a commit will carry, and an add that cached a different package
	// admits a different client
	if !bytes.Equal(cached[0].Proposal.Add.KeyPackage.InitKey, kp.InitKey) {
		t.Fatalf("the cached add publishes init key %x and the key package handed over publishes %x",
			cached[0].Proposal.Add.KeyPackage.InitKey, kp.InitKey)
	}
}

// TestProposeAddRefusesAKeyPackageItsOwnValidatorWouldRefuse is the send side of section 10.1.
//
// The suite is flipped after the package was signed, which is the cheapest reachable refusal of
// (*KeyPackage).Validate that is not the signature itself: version, then ciphersuite, then the
// signature, so this row observes the SUITE clause specifically.
func TestProposeAddRefusesAKeyPackageItsOwnValidatorWouldRefuse(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	bob := testIdentity(t, crypto, "bob")
	kp, _, _ := testKeyPackage(t, crypto, bob)
	kp.CipherSuite = CipherSuiteX25519AesGcm128Sha256Ed25519
	encoded, err := syntax.Marshal(kp)
	if err != nil {
		t.Fatalf("marshal key package: %v", err)
	}
	if _, err := group.ProposeAdd(encoded); !errors.Is(err, errProfileCiphersuite) {
		t.Fatalf("ProposeAdd error = %v, want the ciphersuite refusal (*KeyPackage).Validate makes", err)
	}
	if cached := group.pendingProposalsForTest(); len(cached) != 0 {
		t.Fatalf("a refused add cached %d entries", len(cached))
	}
}

// TestProposeAddRefusesALeafWithNoWrapTarget is the v1 half of the same door, and it is not in
// section 10.1 at all: every commit this profile makes wraps the epoch secret to
// urmessage_leaf_keys, so a joiner whose leaf carries none is a member no epoch can reach.
func TestProposeAddRefusesALeafWithNoWrapTarget(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	bob := testIdentity(t, crypto, "bob")
	kp, _, _, err := NewKeyPackage(crypto, crypto.Suite(), BasicCredential(bob.IdentityPub),
		testCapabilities(), nil)
	if err != nil {
		t.Fatalf("NewKeyPackage with no extensions: %v", err)
	}
	encoded, err := syntax.Marshal(kp)
	if err != nil {
		t.Fatalf("marshal key package: %v", err)
	}
	if _, err := group.ProposeAdd(encoded); !errors.Is(err, ErrMalformedExtension) {
		t.Fatalf("ProposeAdd error = %v, want the leaf keys refusal", err)
	}
}

// TestProposeUpdateUsesAFreshEncryptionKey is the plan's own row: the property an Update exists
// for, read off the cache's copy of what was published.
func TestProposeUpdateUsesAFreshEncryptionKey(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	before := group.OwnLeafNodeCopy()
	if before == nil {
		t.Fatal("OwnLeafNodeCopy returned nil")
	}
	if _, err := group.ProposeUpdate(); err != nil {
		t.Fatalf("ProposeUpdate: %v", err)
	}
	cached := group.pendingProposalsForTest()
	if len(cached) != 1 {
		t.Fatalf("cached = %d, want 1", len(cached))
	}
	if cached[0].Proposal.Update == nil {
		t.Fatal("the cached entry carries no update arm")
	}
	updated := cached[0].Proposal.Update.LeafNode
	if bytes.Equal(updated.EncryptionKey, before.EncryptionKey) {
		t.Fatal("an update that reuses the leaf's encryption key provides no post compromise security")
	}
	if updated.LeafNodeSource != LeafNodeSourceUpdate {
		t.Fatalf("leaf_node_source = %d, want update", updated.LeafNodeSource)
	}
	// the SIGNATURE is over the update variant's own preimage, which carries the group id and the
	// leaf index a key_package leaf's does not. A leaf signed with nil and 0 verifies against
	// itself and against no receiver, and nothing about the value says which it was.
	if err := updated.VerifySignature(crypto, group.GroupId(), group.OwnLeafIndex()); err != nil {
		t.Fatalf("the update leaf does not verify in this group at this leaf: %v", err)
	}
	// the private half is where a committer will look for it
	priv, err := group.store.GetPrivateKey(updated.EncryptionKey)
	if err != nil {
		t.Fatalf("the update's private key was not filed under the key it publishes: %v", err)
	}
	if len(priv) == 0 {
		t.Fatal("the store holds an empty private key for the update's encryption key")
	}
}

// TestProposeUpdateDrawsItsEncryptionKeyFreshAndFromItsOwnDraw is the entropy gate, written against
// what the proposal PUBLISHES rather than against the line that draws.
//
// Three defects it is built to see, each of which leaves the rest of this package green:
//
//  1. the draw replaced by a CONSTANT, or by any value this call did not draw -- the group id, the
//     founding leaf's own ikm, a zero buffer. The key the proposal published is then not derivable
//     from anything the provider was asked for, so the search below finds nothing.
//  2. the draw REUSED from the group's founding, which is the substitution that makes an Update
//     publish a key an attacker who compromised the founding already has. The founding draws are
//     recorded before the call and are excluded explicitly.
//  3. a draw made and THROWN AWAY. Every KDF.Nh draw this call made has to be the one the proposal
//     published, so a second one is a failure here until somebody says what it is for.
//
// The four octet reuse guard SealPrivateMessage draws is not a KDF.Nh draw and is not part of that
// accounting; it is the message's, not the leaf key's.
func TestProposeUpdateDrawsItsEncryptionKeyFreshAndFromItsOwnDraw(t *testing.T) {
	base := testCrypto(t)
	owner := testIdentity(t, base, "owner")
	witness := &entropyWitness{CryptoProvider: base}
	cfg := testGroupConfig(t, witness, owner, "group-1")
	group, err := NewGroup(cfg, owner.SigPriv, BasicCredential(owner.IdentityPub))
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	defer group.Close()

	founding := len(witness.draws)
	foundingIkms := len(witness.ikms)
	if founding == 0 || foundingIkms == 0 {
		t.Fatal("group creation recorded no draws, so the exclusion below excludes nothing")
	}
	if _, err := group.ProposeUpdate(); err != nil {
		t.Fatalf("ProposeUpdate: %v", err)
	}
	drawn := witness.draws[founding:]
	derived := witness.ikms[foundingIkms:]
	if len(derived) != 1 {
		t.Fatalf("ProposeUpdate derived %d key pairs, want the one the replacement leaf is keyed by",
			len(derived))
	}
	at := drawIndexOf(drawn, derived[0])
	if at < 0 {
		t.Fatal("the update leaf's key pair was derived from something this call never drew")
	}
	if drawIndexOf(witness.draws[:founding], derived[0]) >= 0 {
		t.Fatal("the update leaf's key pair was derived from a value this group was FOUNDED on; an update that republishes founding key material provides no post compromise security")
	}
	_, encPub, err := base.DeriveKeyPair(drawn[at])
	if err != nil {
		t.Fatalf("re-derive the update key pair: %v", err)
	}
	cached := group.pendingProposalsForTest()
	if len(cached) != 1 || cached[0].Proposal.Update == nil {
		t.Fatalf("the update was not cached: %d entries", len(cached))
	}
	if published := cached[0].Proposal.Update.LeafNode.EncryptionKey; !bytes.Equal(published, encPub) {
		t.Fatalf("the update publishes %x and draw %d derives %x", published, at, encPub)
	}
	// and nothing of the leaf key's width was drawn that the proposal did not publish
	for i, one := range drawn {
		if i != at && len(one) == base.HashSize() {
			t.Errorf("ProposeUpdate drew a second value of KDF.Nh at %d and published neither it nor anything derived from it; a draw nothing publishes is entropy this gate cannot follow",
				i)
		}
	}
}

// TestTwoGroupsProposeUpdatesUnderDifferentKeys is the divergence half of the entropy claim, and it
// sees one thing the gate above cannot: a draw that IS recorded and IS used and is nevertheless the
// same value every time -- a provider stub, a seeded source, a package level buffer.
func TestTwoGroupsProposeUpdatesUnderDifferentKeys(t *testing.T) {
	crypto := testCrypto(t)
	keys := [][]byte{}
	for _, name := range []string{"owner-a", "owner-b"} {
		owner := testIdentity(t, crypto, name)
		group := testNewGroup(t, crypto, owner, "group-1")
		if _, err := group.ProposeUpdate(); err != nil {
			t.Fatalf("%s: ProposeUpdate: %v", name, err)
		}
		cached := group.pendingProposalsForTest()
		if len(cached) != 1 || cached[0].Proposal.Update == nil {
			t.Fatalf("%s: the update was not cached", name)
		}
		keys = append(keys, bytes.Clone(cached[0].Proposal.Update.LeafNode.EncryptionKey))
		group.Close()
	}
	if bytes.Equal(keys[0], keys[1]) {
		t.Fatalf("two groups proposed updates publishing the same encryption key %x", keys[0])
	}
}

// TestProposeUpdateIsRefusedTwiceInOneEpoch is the section 12.2 ceiling read from the sending side.
//
// One sender contributes at most ONE committable update however many it publishes, because an
// update applies to its own sender's leaf and section 12.2 refuses a list carrying two proposals
// that apply to one leaf. A generator that cached a second would be filling this epoch's cache with
// entries its own commit path cannot carry.
func TestProposeUpdateIsRefusedTwiceInOneEpoch(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	if _, err := group.ProposeUpdate(); err != nil {
		t.Fatalf("the first ProposeUpdate: %v", err)
	}
	if _, err := group.ProposeUpdate(); err == nil {
		t.Fatal("a second update in one epoch was accepted; section 12.2 admits one update per sender per commit")
	}
	if cached := group.pendingProposalsForTest(); len(cached) != 1 {
		t.Fatalf("the cache holds %d updates, want 1", len(cached))
	}
}

// TestProposeRemoveRefusesOwnLeaf is the plan's own row.
//
// The refusal is about this client's CACHE and not about RFC 9420: section 12.1.3's leave flow is a
// member sending a Remove for its own leaf. What this build has no room for is CACHING one, because
// task 13 commits what the cache holds and validateCommitterIsNotRemoved refuses that commit at
// every receiver.
func TestProposeRemoveRefusesOwnLeaf(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()
	if _, err := group.ProposeRemove(group.OwnLeafIndex()); !errors.Is(err, ErrRemoveCommitter) {
		t.Fatalf("ProposeRemove error = %v, want the committer-removal refusal", err)
	}
	if cached := group.pendingProposalsForTest(); len(cached) != 0 {
		t.Fatalf("a refused self remove cached %d entries", len(cached))
	}
}

// TestProposeRemoveRefusesALeafTheTreeDoesNotHold is ValSem108 asked at generation time: a caller
// that named a member who has already been removed, or a leaf beyond the tree, learns it from the
// call it made rather than from a commit nobody accepts.
func TestProposeRemoveRefusesALeafTheTreeDoesNotHold(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()
	if _, err := group.ProposeRemove(LeafIndex(7)); !errors.Is(err, ErrRemoveNonMember) {
		t.Fatalf("ProposeRemove error = %v, want ErrRemoveNonMember", err)
	}
}

// TestProposeGroupContextExtensionsRefusesProfileViolation is the plan's own row, against the
// package's real sentinel: errProfileExternalSender is the stand-in p8's Profile will export, and
// validate_commit.go declares it once for both the sending and the receiving side of ValSem209.
func TestProposeGroupContextExtensionsRefusesProfileViolation(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()
	bad := []Extension{{ExtensionType: ExtensionTypeExternalSenders, ExtensionData: []byte{}}}
	if _, err := group.ProposeGroupContextExtensions(bad); !errors.Is(err, errProfileExternalSender) {
		t.Fatalf("ProposeGroupContextExtensions error = %v, want errProfileExternalSender", err)
	}
	if cached := group.pendingProposalsForTest(); len(cached) != 0 {
		t.Fatalf("a refused extension set cached %d entries", len(cached))
	}
}

// TestProposeGroupContextExtensionsRefusesAnExtensionSetWithNoPolicy is the second door, and it is
// this profile's rather than the RFC's. A group here always carries a urmessage_group_policy, so a
// wholesale replacement that drops it is a group with no owner and no roles -- which nothing
// downstream reports until the first message that needed one.
func TestProposeGroupContextExtensionsRefusesAnExtensionSetWithNoPolicy(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()
	if _, err := group.ProposeGroupContextExtensions(nil); !errors.Is(err, ErrNoGroupPolicy) {
		t.Fatalf("ProposeGroupContextExtensions error = %v, want ErrNoGroupPolicy", err)
	}
}

// TestTheProposalThisGroupCachesSharesNoStorageWithItsCaller is the retention half, and its NAME is
// the correction rather than a detail.
//
// It was written as "ProposeGroupContextExtensions copies the extension bodies it was handed", and
// under that name it could not fail: the generator copied, and so did the cache, one frame further
// down and through the codec -- so deleting the generator's copy left this green, because what the
// assertions read is the CACHE's entry. Two copies, and the test observed the one it was not about.
//
// The property that is real, and the one that matters, is stated over the value that OUTLIVES the
// call. The cached entry is what a later commit carries and what this client will still be holding
// an epoch from now; a caller's array reaching into it is a proposal that changes after the group
// signed it, with the signature going on verifying over the octets as they were and nothing at the
// point of the write to say so. Where the copy is made is the cache's business -- it is the thing
// doing the retaining -- and this reads the property rather than the line.
func TestTheProposalThisGroupCachesSharesNoStorageWithItsCaller(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	handed := testGroupContextOf(t, group).Extensions
	if len(handed) == 0 {
		t.Fatal("the group publishes no extensions, so this test scribbles nothing")
	}
	if _, err := group.ProposeGroupContextExtensions(handed); err != nil {
		t.Fatalf("ProposeGroupContextExtensions: %v", err)
	}
	cached := group.pendingProposalsForTest()
	if len(cached) != 1 || cached[0].Proposal.GroupContextExtensions == nil {
		t.Fatalf("the proposal was not cached: %d entries", len(cached))
	}
	kept := [][]byte{}
	for _, ext := range cached[0].Proposal.GroupContextExtensions.Extensions {
		kept = append(kept, bytes.Clone(ext.ExtensionData))
	}
	scribbled := 0
	for _, ext := range handed {
		for i := range ext.ExtensionData {
			ext.ExtensionData[i] ^= 0xff
			scribbled += 1
		}
	}
	if scribbled == 0 {
		t.Fatal("every extension handed over had an empty body, so nothing was scribbled")
	}
	for at, ext := range cached[0].Proposal.GroupContextExtensions.Extensions {
		if !bytes.Equal(ext.ExtensionData, kept[at]) {
			t.Errorf("extension %d of the cached proposal held %x before its caller wrote into its own array and %x afterwards",
				at, kept[at], ext.ExtensionData)
		}
	}
}

// TestAClosedGroupProposesNothing is the ender's half. A closed group has zeroized its schedule and
// its secret tree, so a proposal path that reached either would be sealing under erased keys or
// dereferencing nil -- and the answer a library gives there must be a refusal, not a panic.
//
// EVERY ARGUMENT BELOW IS ONE AN OPEN GROUP WOULD ALSO REFUSE, and that is what makes each row
// observe the generator's OWN closed check rather than the one in propose. With a good argument a
// closed group answers errGroupClosed either way -- propose refuses last -- so the rows would pass
// against a generator that had stopped asking, and the two checks would be guards covering for each
// other, which is the shape proposal_list.go's own header rejects. With a bad one they separate: a
// generator that judged its argument first answers the argument's refusal, and a caller repairing
// what it was told about goes on getting the same answer from a group that was never going to act.
//
// The store is read afterwards because ProposeUpdate is the one generator that WRITES before it
// publishes: the private half is filed before the proposal is framed, so a closed group that got as
// far as the draw leaves a key in its caller's store for an epoch it can never reach.
func TestAClosedGroupProposesNothing(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	store, isTestStore := group.store.(*testStore)
	if !isTestStore {
		t.Fatalf("this group's store is a %T and this test reads the fixture's own", group.store)
	}
	filedBefore := len(store.privs)
	if err := group.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rows := map[string]func() ([]byte, error){
		// octets no decoder accepts
		"ProposeAdd": func() ([]byte, error) { return group.ProposeAdd(nil) },
		// the one generator with no argument to get wrong; what its own check buys is below
		"ProposeUpdate": group.ProposeUpdate,
		// a leaf this group never held
		"ProposeRemove": func() ([]byte, error) { return group.ProposeRemove(LeafIndex(7)) },
		// an extension the v1 profile refuses in a group context
		"ProposeGroupContextExtensions": func() ([]byte, error) {
			return group.ProposeGroupContextExtensions(
				[]Extension{{ExtensionType: ExtensionTypeExternalSenders, ExtensionData: []byte{}}})
		},
	}
	for name, call := range rows {
		if _, err := call(); !errors.Is(err, errGroupClosed) {
			t.Errorf("%s on a closed group answered %v, want the closed refusal", name, err)
		}
	}
	if filed := len(store.privs); filed != filedBefore {
		t.Errorf("a closed group's refused update left %d private keys in its caller's store and there were %d before",
			filed, filedBefore)
	}
}
