// RFC 9420 section 11 group creation, and the state one group at one epoch carries.
//
// THE GROUP IS THE ONLY STATEFUL EXPORTED TYPE IN THIS PACKAGE, and every other type here is a
// value the group assembles or is handed. It is NOT safe for concurrent use: connect/message
// serializes every call through a single goroutine command loop, and stateLock is here so that
// misuse fails loudly under -race rather than tearing a tree in half.
//
// WHY CREATION IS THE RFC'S FOUR STEPS AND NOT A SHORTCUT. Section 11 could be read as "choose a
// tree, choose an epoch secret, done", and the RFC says in as many words why it is not written
// that way: the long form "removes unnecessary choices, by which, for example, bad randomness
// could be introduced". Every field NewGroup writes is a field nothing else in this package has
// ever validated -- there is no peer, no signature and no vector on the other side of a group
// creation -- so each of the four steps is spelled out here in the order the RFC gives them, and
// each value a step draws is held by a test that can see the draw through what the group
// PUBLISHES rather than by naming the line that made it.
//
// WHAT THE CACHE BINDS TO IS A VERIFIED CONTEXT AND NOT THE ONE THIS FUNCTION JUST BUILT.
// NewProposalCache takes a *VerifiedGroupContext, whose only constructor is
// (*GroupInfo).VerifiedContext, and the creator is not exempt from that: it assembles the epoch 0
// GroupInfo, signs it with its own signature key, and verifies it against its own tree. That is
// nearly a tautology for the creator -- it is the only member, so the tree it checks against holds
// only its own leaf -- and it is written that way ON PURPOSE. The alternative is a second door
// onto a verified context, and group_context_verified.go spent four rounds establishing that the
// second door IS the defect; a door used only by the one caller entitled to it is still a door.
// TestEveryConstructionOfAVerifiedGroupContextIsClassifiedHere fails on the day this file spells
// the construction directly.
package mls

import (
	"errors"
	"fmt"
	"sync"

	"github.com/urnetwork/connect/mls/syntax"
)

// The refusals group creation makes that are nobody else's.
//
// One value per rule, for errors_lifecycle.go's reason: errors.Is cannot tell two rules apart when
// they answer the same value, so a test asserting the broad question passes over a rule that fired
// for the wrong reason.
//
// errGroupConfigProviderSuite is NOT errProfileCiphersuite, and the difference is the whole reason
// it exists. The profile refusal is "this build does not create groups under that suite", which is
// a decision this profile made and could revisit; this one is "the config names one suite and the
// provider handed in runs another", which is a caller that wired two objects together wrongly and
// has nothing to do with the profile. Collapsing them would hand a caller reading "outside the v1
// profile" a suite that is squarely inside it.
var (
	errNilGroupConfig = errors.New("mls: there is no group config")
	errNilStateStore  = errors.New("mls: the group config carries no state store")

	errGroupConfigProviderSuite = errors.New("mls: the group config's ciphersuite is not the provider's")

	errGroupClosed = errors.New("mls: the group is closed and its epoch secrets have been zeroized")

	errCreationConfirmationTag = errors.New("mls: the epoch 0 confirmation tag is not a tag of this suite's width")
)

// StateStore persists group state and private key material across process restarts. It is
// deliberately dumb -- no queries, no cross-group transactions -- so that sdk can implement it over
// the sealed local store without leaking storage semantics into the crypto. Spec A section 3.5.
type StateStore interface {
	PutGroupState(groupId []byte, epoch uint64, state []byte) error
	GetGroupState(groupId []byte, epoch uint64) ([]byte, error)
	DeleteGroupStateBefore(groupId []byte, epoch uint64) error

	PutPrivateKey(pub []byte, priv []byte) error
	GetPrivateKey(pub []byte) ([]byte, error)
	DeletePrivateKey(pub []byte) error

	PutKeyPackage(ref []byte, kp []byte, initPriv []byte, encPriv []byte) error
	TakeKeyPackage(ref []byte) (kp, initPriv, encPriv []byte, err error)
}

// GroupConfig is everything a group needs that is not epoch state.
//
// Profile is a *profile and not a *Profile because p8 owns that type; see proposal_list.go's
// header for why the stand-in is unexported and what the swap costs. A caller outside this package
// leaves the field nil and gets defaultProfile(), which is the only profile this build has.
type GroupConfig struct {
	Suite        CipherSuite
	GroupId      []byte
	Extensions   []Extension
	RequiredCaps RequiredCapabilities
	Crypto       CryptoProvider
	Store        StateStore
	Profile      *profile
	LeafKeys     LeafKeysExtension
}

// Member is one member of the group as the product sees it.
type Member struct {
	LeafIndex    LeafIndex
	IdentityPub  []byte
	SignatureKey SignaturePublicKey
	LeafKeys     *LeafKeysExtension
	Role         Role
}

// EpochSecretName is a CLOSED enum. MASTER section 8.2 needs exactly these two for archive_secret,
// and exporting epoch_secret instead would also expose confirmation_key and membership_key. An
// open string accessor would invite exactly that mistake, so there is no such accessor.
type EpochSecretName uint8

const (
	EpochSecretSenderData EpochSecretName = iota + 1
	EpochSecretEncryption
)

// restoreKind discriminates what the persisted state carries so that task 19's LoadGroup can
// rebuild the key schedule. Epoch 0 has no joiner secret and every later epoch does; there is no
// third case.
type restoreKind uint8

const (
	restoreFromEpochSecret restoreKind = 1
	restoreFromJoiner      restoreKind = 2
)

// createSuiteProfile is the v1 disposition of every REGISTERED ciphersuite AS A SUITE TO CREATE A
// GROUP UNDER: nil for the one spec A section 3.1 admits, and the sentinel naming why for the one
// it does not.
//
// A map keyed by the registry's own constants rather than a comparison against one name, for
// groupExtensionProfile's reason next door: the accepted set is the complement of a refused set,
// and only one of the two can be written down without understating the other. What holds it to the
// registry is TestTheV1ProfileClassifiesEveryRegisteredCiphersuiteForCreation, which reads Suites()
// -- the registry itself -- and compares the two sets in both directions.
//
// 0x0001 is REGISTERED AND IMPLEMENTED and still refused here, and that is the whole content of
// this table. A profile that refused only an unimplemented suite would be saying nothing.
var createSuiteProfile = map[CipherSuite]error{
	CipherSuiteX25519AesGcm128Sha256Ed25519: errProfileCiphersuite,
	CipherSuiteX25519ChaCha20Sha256Ed25519:  nil,
}

// checkCiphersuiteForCreate is the one refusal surface for the suite a group is created under,
// standing in for (*Profile).CheckCiphersuiteForCreate.
//
// It is a method on proposal_list.go's profile rather than a free function, for
// checkGroupExtension's reason: the narrowing is the PROFILE's and not this file's, and p8's
// Profile carries all seven Check* gates beside each other.
//
// The two refusals are separated for checkProposalType's reason. A code point this build has never
// heard of is ErrUnknownCipherSuite -- there is no narrowing to name -- and a REGISTERED one this
// profile will not create under is the profile sentinel, which is a decision that could be
// revisited.
func (self *profile) checkCiphersuiteForCreate(suite CipherSuite) error {
	refusal, registered := createSuiteProfile[suite]
	if !registered {
		return fmt.Errorf("%w: ciphersuite %#04x is not in this build's suite registry",
			ErrUnknownCipherSuite, uint16(suite))
	}
	if refusal != nil {
		return fmt.Errorf("%w: ciphersuite %#04x may not be used to create a group",
			refusal, uint16(suite))
	}
	return nil
}

// Group is one MLS group at one epoch.
//
// THE KEY SCHEDULE FIELD IS SPELLED schedule. p6 task 20's two construction-bypass seams were
// written against self.keySchedule and p7's plan declares self.schedule; p7 owns this struct, so
// schedule is what it is, and task 20 compiles against this name.
type Group struct {
	stateLock sync.Mutex

	// the STORE and not the *GroupConfig it came off. A config is a caller's own structure and
	// the caller goes on holding it -- to found a second group, or to write a fresh group id into
	// for the next one -- so a group that kept the pointer would be reading a value somebody else
	// is still editing, and every octet reachable from that config would be storage this group
	// and its caller share. Nothing here ever needed the rest of it: the suite, the extensions and
	// the leaf keys are read once during creation and the store is the only field that outlives
	// the call. TestNoConstructionOfSealedStorageRetainsItsCallersArrays is what holds this to
	// one field.
	store  StateStore
	crypto CryptoProvider
	signer SignaturePrivateKey
	cred   Credential

	ownLeaf    LeafIndex
	ownPriv    *TreeKEMPrivate
	tree       *RatchetTree
	context    *GroupContext
	schedule   *KeySchedule
	secretTree *SecretTree
	transcript *TranscriptHashes
	proposals  *ProposalCache

	// which constructor this epoch's schedule came from, which is what task 19's LoadGroup needs
	// in order to know what to rebuild it from. THE SECRET ITSELF IS NOT HERE, and that is the
	// decision rather than an omission: the schedule above already retains the epoch secret, its
	// erase is held by TestZeroizeErasesEveryByteSliceThisTypeDeclares over the type that
	// DECLARES that storage, and a second copy parked on this struct would be the same secret
	// held by nothing but a hand written Close. Task 19 rebuilds from self.schedule.
	restoreKind restoreKind

	closed bool
}

// NewGroup creates a one-member group by RFC 9420 section 11's four steps.
//
// The steps are numbered in the body against the RFC's own list. What is worth reading them for is
// the ORDER: the tree exists before the group context, because the context carries the tree hash;
// the context exists before the key schedule, because every secret is expanded over the context;
// and the confirmation tag exists before the interim transcript hash, because the interim hash is
// taken over it. Each of those is a dependency and not a preference, and an implementation that
// reordered any of them would produce a group that is self consistent and agrees with nobody.
func NewGroup(cfg *GroupConfig, signer SignaturePrivateKey, cred Credential) (*Group, error) {
	if cfg == nil {
		return nil, errNilGroupConfig
	}
	crypto := cfg.Crypto
	// refused rather than dereferenced, and refused first: every value below is drawn, derived or
	// signed through the provider, so there is nothing this function could judge without one
	if crypto == nil {
		return nil, fmt.Errorf("%w: every secret this group is founded on is drawn through it",
			ErrNilCryptoProvider)
	}
	if cfg.Store == nil {
		return nil, errNilStateStore
	}
	active := cfg.Profile
	if active == nil {
		active = defaultProfile()
	}
	if err := active.checkCiphersuiteForCreate(cfg.Suite); err != nil {
		return nil, err
	}
	// the suite the config names must be the suite the provider runs. Without this the
	// disagreement surfaces four steps later inside (*GroupInfo).Verify, as a tree hash taken with
	// one suite's hash function checked against another's -- a refusal naming the tree, over a
	// tree that is perfectly good.
	if cfg.Suite != crypto.Suite() {
		return nil, fmt.Errorf("%w: the config names %#04x and the provider runs %#04x",
			errGroupConfigProviderSuite, uint16(cfg.Suite), uint16(crypto.Suite()))
	}
	for _, ext := range cfg.Extensions {
		if err := active.checkGroupExtension(ext.ExtensionType); err != nil {
			return nil, err
		}
	}
	// a group this profile creates carries a policy. GroupPolicyOf answers ErrNoGroupPolicy for a
	// context that carries none, which is a different fault from a malformed one, and it is
	// answered here rather than at the first message that needed a role.
	if _, err := GroupPolicyOf(cfg.Extensions); err != nil {
		return nil, err
	}
	leafKeysExt, err := cfg.LeafKeys.Encode()
	if err != nil {
		return nil, err
	}

	// step 1: a one-member tree, epoch 0, and the zero-length confirmed transcript hash.
	//
	// The founding leaf's HPKE key pair is DRAWN HERE and is one of the two values this whole
	// function is trusted with. A constant in place of this draw still encrypts, still decrypts,
	// still round trips, and matches every vector that does not depend on the randomness -- which
	// is why what holds it is a test that reads the draw back out of what the group publishes
	// rather than one that asserts over this line.
	encPriv, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		return nil, err
	}
	leaf, err := NewLeafNode(crypto, signer, cred, encPub, v1Capabilities(), []Extension{leafKeysExt})
	if err != nil {
		return nil, err
	}
	tree := NewRatchetTree()
	ownLeaf, err := tree.AddLeaf(leaf)
	if err != nil {
		return nil, err
	}
	treeHash, err := tree.TreeHash(crypto)
	if err != nil {
		return nil, err
	}
	// the extension BODIES are copied and not the entries alone. append copies the Extension
	// STRUCTS and leaves every ExtensionData pointing at the caller's octets, so a caller that
	// went on writing into the buffer its policy was encoded out of would be rewriting the
	// context this group PUBLISHES -- while the key schedule stays derived over the octets as
	// they were, because the epoch secrets were expanded over the context at creation. That is a
	// group whose published context and whose epoch secrets have parted company, with every
	// signature still verifying at the moment it was made and nothing in between to point at.
	// Nil is kept distinct from empty for cloneBytes's reason, and GroupContext.Clone copies the
	// bodies the same way for the same reason one epoch later.
	var extensions []Extension
	if cfg.Extensions != nil {
		extensions = make([]Extension, 0, len(cfg.Extensions))
		for _, extension := range cfg.Extensions {
			extensions = append(extensions, Extension{
				ExtensionType: extension.ExtensionType,
				ExtensionData: cloneBytes(extension.ExtensionData),
			})
		}
	}
	if len(cfg.RequiredCaps.ExtensionTypes) != 0 || len(cfg.RequiredCaps.ProposalTypes) != 0 ||
		len(cfg.RequiredCaps.CredentialTypes) != 0 {
		requiredExt, requiredErr := encodeRequiredCapabilities(&cfg.RequiredCaps)
		if requiredErr != nil {
			return nil, requiredErr
		}
		extensions = append([]Extension{requiredExt}, extensions...)
	}
	context := &GroupContext{
		Version:     ProtocolVersionMls10,
		CipherSuite: cfg.Suite,
		GroupId:     cloneBytes(cfg.GroupId),
		Epoch:       0,
		TreeHash:    treeHash,
		// section 11: "Confirmed transcript hash: The zero-length octet string". NOT KDF.Nh zero
		// octets and not the hash of nothing -- the three are different values, all of them well
		// formed, and the first commit's confirmed hash is chained from this one, so a wrong
		// value here is invisible until a second member has to agree with it.
		ConfirmedTranscriptHash: []byte{},
		Extensions:              extensions,
	}

	// step 2: a fresh random epoch secret of size KDF.Nh, and the key schedule under it.
	//
	// The second of the two values this function is trusted with, and the one a substitution is
	// most invisible in: every derived secret goes on being a well formed secret of the right
	// length. It is not retained HERE -- NewKeyScheduleFromEpochSecret keeps its own copy, which
	// is what task 19 rebuilds from -- so this local is the only other reference and it dies with
	// the call. Guardrail 6: no exported symbol of this package answers it.
	epochSecret := crypto.Random(crypto.HashSize())
	schedule, err := NewKeyScheduleFromEpochSecret(crypto, epochSecret, context)
	if err != nil {
		return nil, err
	}

	// steps 3 and 4: the confirmation tag over the empty confirmed transcript hash, and then the
	// interim transcript hash from it.
	//
	// SetFromGroupInfo is the JOINER's half of this and cannot be used here: it refuses a
	// confirmed transcript hash that is not KDF.Nh octets, which is right for a value that came
	// off somebody else's wire and is wrong for the one value section 11 defines as empty.
	transcript := InitialTranscriptHashes()
	confirmationTag := schedule.ConfirmationTag(transcript.Confirmed)
	// ConfirmationTag answers nil for an epoch whose confirmation_key has been erased. Nothing can
	// have erased this one -- the schedule was built four statements ago -- so this is a refusal
	// over a build that has stopped agreeing with itself, and the alternative to making it is
	// folding a nil tag into the interim hash and founding a group nobody can join.
	if len(confirmationTag) != crypto.HashSize() {
		return nil, fmt.Errorf("%w: the schedule answered %d octets, want %d",
			errCreationConfirmationTag, len(confirmationTag), crypto.HashSize())
	}
	interim, err := InterimTranscriptHash(crypto, transcript.Confirmed, confirmationTag)
	if err != nil {
		return nil, err
	}
	transcript.Interim = interim

	secretTree, err := NewSecretTree(crypto, tree.LeafWidth(), schedule.Secrets().Encryption)
	if err != nil {
		return nil, err
	}

	// the proposal cache binds to a context this client has VERIFIED, and the creator earns that
	// the same way every other member does: it publishes the epoch 0 GroupInfo, signs it, and
	// checks the signature against the tree. See this file's header for why the creator gets no
	// shortcut past the one door.
	groupInfo := &GroupInfo{
		GroupContext:    *context,
		ConfirmationTag: confirmationTag,
		Signer:          ownLeaf,
	}
	if err := groupInfo.Sign(crypto, signer); err != nil {
		return nil, err
	}
	verified, err := groupInfo.VerifiedContext(crypto, tree)
	if err != nil {
		return nil, err
	}
	proposals, err := NewProposalCache(verified)
	if err != nil {
		return nil, err
	}

	group := &Group{
		store:  cfg.Store,
		crypto: crypto,
		// the signing key and the identity are COPIED, for NewLeafNode's reason one layer up:
		// both are arrays the caller owns and goes on using, and this group signs with the key
		// and names itself with the identity for the whole of its life. A group holding a view
		// over either is a group whose signatures start failing at the moment its caller reuses
		// its own buffer, one epoch after the mistake.
		signer:      SignaturePrivateKey(cloneBytes(signer)),
		cred:        Credential{CredentialType: cred.CredentialType, Identity: cloneBytes(cred.Identity)},
		ownLeaf:     ownLeaf,
		ownPriv:     NewTreeKEMPrivate(ownLeaf, encPriv),
		tree:        tree,
		context:     context,
		schedule:    schedule,
		secretTree:  secretTree,
		transcript:  transcript,
		proposals:   proposals,
		restoreKind: restoreFromEpochSecret,
	}
	if err := group.persist(); err != nil {
		return nil, err
	}
	return group, nil
}

// v1Capabilities is what every v1 leaf advertises: one version, every registered suite, no optional
// proposal types, the three URmessage extensions, and basic credentials only.
//
// Suites() rather than the group's own code point, for the reason lifecycle_fixtures_test.go's
// testCapabilities gives: the vector says what this member CAN do and not what this group runs, and
// a member advertising only its own group's suite is a member no other suite could ever add.
func v1Capabilities() Capabilities {
	return Capabilities{
		Versions:     []ProtocolVersion{ProtocolVersionMls10},
		CipherSuites: Suites(),
		Extensions: []ExtensionType{
			ExtensionTypeUrmessageGroupPolicy,
			ExtensionTypeUrmessageLeafKeys,
			ExtensionTypeUrmessageOwnerSuccessor,
		},
		Proposals:   []ProposalType{},
		Credentials: []CredentialType{CredentialTypeBasic},
	}
}

// encodeRequiredCapabilities serializes the section 11.1 required_capabilities extension.
func encodeRequiredCapabilities(required *RequiredCapabilities) (Extension, error) {
	data, err := syntax.Marshal(required)
	if err != nil {
		return Extension{}, err
	}
	return Extension{ExtensionType: ExtensionTypeRequiredCapabilities, ExtensionData: data}, nil
}

// GroupId returns the group's identifier, as storage the caller owns.
func (self *Group) GroupId() []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return cloneBytes(self.context.GroupId)
}

// Epoch returns the current epoch.
func (self *Group) Epoch() uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.context.Epoch
}

// OwnLeafIndex returns this device's leaf.
func (self *Group) OwnLeafIndex() LeafIndex {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.ownLeaf
}

// OwnLeafNodeCopy returns a deep copy of this device's leaf. It is a Clone and never the live leaf:
// the validation plan's forge mutates what it is handed, and handing it the tree's own leaf would
// corrupt the tree this epoch's tree hash was taken over, from a test.
func (self *Group) OwnLeafNodeCopy() *LeafNode {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	leaf := self.tree.Leaf(self.ownLeaf)
	if leaf == nil {
		return nil
	}
	return leaf.Clone()
}

// Members returns a snapshot of the membership with roles resolved from the group policy extension.
func (self *Group) Members() []Member {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.membersLocked()
}

// membersLocked is Members with the state lock already held.
//
// A member whose identity the policy does not name is RoleMember and not a refusal. The policy
// names the members that hold a role other than the default, so a tree position with no row is a
// position with the default role rather than a group that has stopped parsing.
func (self *Group) membersLocked() []Member {
	policy, policyErr := GroupPolicyOf(self.context.Extensions)
	out := []Member{}
	for _, leafIndex := range self.tree.NonBlankLeaves() {
		leaf := self.tree.Leaf(leafIndex)
		if leaf == nil {
			continue
		}
		// EVERY array of this snapshot is copied, and the two beside each other are why that is
		// said rather than left to be read off the lines: an identity that is cloned and a
		// signature key that is not are one struct three lines apart, and the second one is a
		// window onto the LIVE ratchet tree. A caller handed that window writes through it into
		// the tree this epoch's tree hash was taken over -- the same hazard OwnLeafNodeCopy
		// answers a Clone for -- and nothing in this package would report it, because the tree
		// goes on being self consistent with the octets it now holds.
		member := Member{
			LeafIndex:    leafIndex,
			IdentityPub:  cloneBytes(leaf.Credential.Identity),
			SignatureKey: SignaturePublicKey(cloneBytes(leaf.SignatureKey)),
			Role:         RoleMember,
		}
		if keys, keysErr := LeafKeysOf(leaf); keysErr == nil {
			member.LeafKeys = keys
		}
		if policyErr == nil {
			if role, named := policy.RoleOf(leaf.Credential.Identity); named {
				member.Role = role
			}
		}
		out = append(out, member)
	}
	return out
}

// MemberAt returns one member.
func (self *Group) MemberAt(leafIndex LeafIndex) (Member, bool) {
	for _, member := range self.Members() {
		if member.LeafIndex == leafIndex {
			return member, true
		}
	}
	return Member{}, false
}

// EpochAuthenticator is the value two members compare to detect a fork, or nil for a closed group.
//
// Nil rather than a panic, and nil rather than the zeros a zeroized schedule holds: a closed
// group's authenticator is not a shorter authenticator, it is no answer at all, and KDF.Nh zero
// octets is a value any two closed groups would agree on.
func (self *Group) EpochAuthenticator() []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil
	}
	return cloneBytes(self.schedule.Secrets().EpochAuthenticator)
}

// Export is the RFC 9420 section 8.5 exporter. MASTER section 7 derives mls_secret from it.
func (self *Group) Export(label string, context []byte, length int) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, errGroupClosed
	}
	return self.schedule.Export(label, context, length)
}

// EpochSecret exposes exactly the two secrets MASTER section 8.2 needs and refuses every other
// name. The default arm is a refusal rather than a zero value, so a caller that invented a third
// name is told so instead of being handed an empty slice it would go on to treat as a key.
func (self *Group) EpochSecret(name EpochSecretName) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, errGroupClosed
	}
	secrets := self.schedule.Secrets()
	switch name {
	case EpochSecretSenderData:
		return cloneBytes(secrets.SenderData), nil
	case EpochSecretEncryption:
		return cloneBytes(secrets.Encryption), nil
	}
	return nil, fmt.Errorf("mls: epoch secret name %d is not in the closed enum", name)
}

// RatchetTree returns the encoded public tree, for out-of-band Welcome delivery and for MASTER
// section 8.2's per-epoch snapshot record.
//
// The tree is the one structure not bounded by the codec's 1 MiB default, so it is written under
// MaxRatchetTreeLength -- the same bound UnmarshalRatchetTree reads it back at.
func (self *Group) RatchetTree() ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := ValSem300NoTrailingBlankNodes(self.tree); err != nil {
		return nil, err
	}
	return syntax.MarshalLimit(self.tree, syntax.MaxRatchetTreeLength)
}

// GroupContext returns the serialized GroupContext for the current epoch. Every framing entry point
// takes these bytes rather than the struct, because a group context is inlined into
// FramedContentTBS with no framing of its own and a second encoding of it is a second answer.
func (self *Group) GroupContext() ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return syntax.Marshal(self.context)
}

// GroupPolicy returns the parsed urmessage_group_policy extension.
func (self *Group) GroupPolicy() (*GroupPolicyExtension, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return GroupPolicyOf(self.context.Extensions)
}

// Close releases the group. Epoch state stays in the store; the secrets held in memory are zeroized
// and dropped.
//
// It is idempotent, because a caller that closes twice -- a deferred close beside an explicit one
// -- has made no mistake, and because Zeroize on a schedule that is already gone would be a nil
// dereference in a cleanup path.
//
// //go:noinline for secret_zeroize.go's reason, which is the class rather than this body: these
// stores are dead in the compiler's reading -- nothing reads the schedule afterwards -- and the
// directive is the only thing between them and a compiler entitled to delete them.
//
//go:noinline
func (self *Group) Close() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = true
	if self.schedule != nil {
		self.schedule.Zeroize()
	}
	if self.secretTree != nil {
		self.secretTree.Zeroize()
	}
	self.schedule = nil
	self.secretTree = nil
	return nil
}

// persist writes the current epoch's state blob.
//
// Called with the state lock held, or before the group has been handed to anybody, which is the
// creation path's case. Task 19 defines the blob and the past-epoch window; this task writes only
// the current epoch.
func (self *Group) persist() error {
	blob, err := self.marshalState()
	if err != nil {
		return err
	}
	return self.store.PutGroupState(self.context.GroupId, self.context.Epoch, blob)
}

// marshalState is TASK 19's and this is the stand-in.
//
// It writes the group context and the tree, which is what the creation test needs in order to see
// that the write happened at all. Task 19 replaces it with the full blob -- the secret a restore
// rebuilds the schedule from, the transcript, the own-leaf private key -- and with the round trip
// test that makes a blob worth writing. Two opaque fields under the MLS varint prefix and not the
// record layer's fixed width one: this is an MLS encoder, and the two are never interchangeable.
//
// The RAISED bound, and it is a capacity rather than an acceptance rule. These octets are this
// client's own local state and never travel, and the tree inside them is written by tree.go's own
// encoder at MaxRatchetTreeLength -- so a default-limit writer here would refuse to persist a
// group this build is entitled to hold, at 500 members, and would refuse it only on the largest
// group anybody ever made.
func (self *Group) marshalState() ([]byte, error) {
	tree, err := syntax.MarshalLimit(self.tree, syntax.MaxRatchetTreeLength)
	if err != nil {
		return nil, err
	}
	context, err := syntax.Marshal(self.context)
	if err != nil {
		return nil, err
	}
	w := syntax.NewWriterLimit(syntax.MaxRatchetTreeLength)
	w.WriteOpaque(context)
	w.WriteOpaque(tree)
	return w.Bytes()
}
