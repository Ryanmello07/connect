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
	"time"

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

	// and the same refusal one epoch on. A SECOND VALUE and not errCreationConfirmationTag,
	// for this block's stated reason: the epoch 0 condition is a group that could not be
	// founded and this one is a commit that could not be built, and a caller reading one
	// value cannot tell which of its calls is the one that failed.
	errCommitConfirmationTag = errors.New("mls: the commit's confirmation tag is not a tag of this suite's width")
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

	ownLeaf LeafIndex
	ownPriv *TreeKEMPrivate
	tree    *RatchetTree
	context *GroupContext
	// the same context with its authority established, which is the only thing the proposal
	// cache binds an epoch to. It is held BESIDE the context rather than in place of it because
	// the two answer different questions -- every read of this epoch wants the fields, and only
	// the cache boundary wants the authority -- and because VerifiedGroupContext hands out a
	// Clone rather than its own pointer, so a group that kept only this one would rebuild the
	// context it publishes on every read.
	//
	// WHAT KEEPS THE TWO FROM PARTING COMPANY is that one statement list writes both: NewGroup
	// builds them from the same GroupInfo and MergePendingCommit installs both off the same
	// staged commit, which is what the epoch mover gate reads.
	verified *VerifiedGroupContext
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

	// the commit this client has built and not yet merged, or the one it has staged out of a
	// peer's commit. AT MOST ONE, because the delivery service accepts at most one commit per
	// (group, epoch): a client holding two candidate epochs has nothing to say which of them
	// the service accepted, and (*Group).Commit refuses a second rather than replacing the
	// first. ClearPendingCommit is how a caller drops one.
	pending *StagedCommit

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
	// AND THE ASSEMBLED LIST IS READ BACK THROUGH THE LOOKUP EVERY LATER DOOR READS IT THROUGH.
	//
	// This is not a second opinion about the caller's extensions -- checkGroupExtension has already
	// judged each of them, and GroupPolicyOf has already refused a repeated policy. It is about the
	// entry THIS FUNCTION ADDS. The prepend above does not ask whether the caller's own list already
	// carries a required_capabilities, so a config that both sets RequiredCaps and supplies the
	// encoded extension founds a group whose context carries the type twice -- and every door that
	// reads it afterwards reaches it through FindExtension, which refuses a repeat. Measured: such a
	// group is created, persisted and signed, and then ValidateProposalList over its OWN published
	// context answers "the extensions vector carries one type at entry 0 and again at entry 2" for
	// every proposal list anyone ever builds against it. A group nobody can validate a proposal in,
	// founded successfully, with nothing at the point of the mistake to point at.
	//
	// The same repair as (*Group).ProposeGroupContextExtensions makes at the other end of the
	// group's life, and for the same reason: a list this build EMITS must be one its own readers
	// accept. TestNewGroupFoundsAContextItsOwnProposalDoorsAccept is what says so, by running the
	// door rather than by counting entries.
	if _, err := requiredCapabilitiesOf(extensions); err != nil {
		return nil, err
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
		verified:    verified,
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

// senderDataSecretLocked is EpochSecret's sender_data arm with the state lock already held, which
// is membersLocked's relationship to Members one section up.
//
// It answers the schedule's OWN slice rather than a copy, because the one caller seals with it and
// keeps nothing: EpochSecret copies because it hands the secret to somebody outside this package,
// and a copy here would be a second live copy of an epoch secret for the length of a seal.
//
// IT IS A DECLARATION AND NOT AN INLINE READ, and that is worth writing down because it looks like
// one. The labelled composition walk in labelled_composition_test.go taints every value read off a
// field that carries a serialized structure -- self.schedule does, since
// NewKeyScheduleFromEpochSecret is a producer in that walk -- and it taints through a method call
// on the tainted receiver, so an inline self.schedule.Secrets().SenderData handed to
// SealPrivateMessage reads there as the serialized GROUP CONTEXT arriving at a labelled field with
// nothing bounding it. It is not that: it is KDF.Nh octets of ExpandWithLabel output, and it enters
// the AEAD as a key derivation input rather than as a labelled field. A call into a declaration of
// this package is a frame of its own to that walk, which is where the two stop being one value, and
// this frame is walked in its turn rather than being a place the question is skipped.
func (self *Group) senderDataSecretLocked() []byte {
	return self.schedule.Secrets().SenderData
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
//
// The group id is CLONED on the way out, for the reason GroupId() clones on the way out. The store
// is an object the caller supplies and goes on holding -- the sdk writes these implementations
// over its own sealed local store -- so a store that keeps the slice it was handed, to key a map
// or to build a path with later, shares an array with this group for the group's lifetime, and a
// write through it rewrites the group id every epoch secret of this group was derived over.
// Nothing downstream would report that: the context stays self consistent with the octets it now
// holds, and the transcript, the tree hash and the key schedule all go on agreeing with each
// other over the wrong id.
func (self *Group) persist() error {
	blob, err := self.marshalState()
	if err != nil {
		return err
	}
	return self.store.PutGroupState(cloneBytes(self.context.GroupId), self.context.Epoch, blob)
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

// ---------------------------------------------------------------------------
// RFC 9420 section 12.1: proposal generation
// ---------------------------------------------------------------------------

// THE FOUR METHODS BELOW ARE THE SENDING SIDE OF EVERY RULE THIS PACKAGE'S RECEIVE PATH ALREADY
// ENFORCES, and that symmetry is the design rather than a property somebody hoped for.
// validate_proposals.go holds ValSem101-113 and section 12.1.2's two rules on an Update's own leaf;
// validate_commit.go holds ValSem200-209; (*ProposalCache).Store holds the v1 profile, the epoch
// binding and section 12.2's ceilings. A generator that emitted a proposal any of those would
// refuse is a client publishing a message its own package will not process, and the refusal arrives
// at a PEER, one commit later, with nothing at the point of the mistake to point at.
//
// So a proposal built here goes through this package's own doors before it is returned:
//
//   - checkProposalProfile, before a single octet is signed;
//   - the structure's own validator for the two kinds that carry one a peer will judge --
//     (*KeyPackage).Validate for an add, GroupPolicyOf for a group context extension set;
//   - ValidateProposalList itself, over a list holding this one proposal, which is section 12.2's
//     whole procedure asked at generation time and is the door the three above cannot stand in
//     for -- see (*Group).propose;
//   - and the CACHE, which re-runs the profile gate, checks the epoch binding and applies the
//     per sender and per leaf ceilings.
//
// TestEveryProposalThisGroupGeneratesIsAcceptedByItsOwnValidationDoors is what holds the claim, by
// putting each generated proposal through ValidateProposalList rather than by asserting over the
// calls made here. A proposal this package refuses to validate is a finding about the generator.
//
// AND ONE GATE DOES ASSERT OVER THE CALLS, deliberately, because the sentence above is stated over
// the four methods that exist rather than over the class of them.
// TestEveryProposalGeneratorOnThisGroupSendsWhatItEmitsThroughItsOwnDoors derives that class --
// every exported method of *Group that puts a message of content type proposal on the wire -- and
// requires each member to reach ValidateProposalList. Measured, which is why it is here: a FIFTH
// generator doing its own framing, signing, sealing and Store passes every dynamic obligation in
// group_test.go while emitting a proposal these doors refuse, because those obligations are
// reached through this method and it is not.
//
// EPOCH STATE IS UNTOUCHED. A proposal is a request and not a change: nothing below writes the
// tree, the group context, the transcript or the key schedule, and the epoch a caller reads after
// proposing is the epoch it read before. Two things DO move, and both are meant to. The sender's
// own message ratchet advances a generation, exactly as an application message would -- a proposal
// is an ordinary PrivateMessage on the wire and is meant to be indistinguishable from one -- and
// the proposal cache grows the entry a later commit will name.
//
// THE PROFILE IS defaultProfile() AND NOT ONE THE GROUP KEPT, which is this package's convention
// and not an omission here. `profile` is an empty struct with one constructor, so every profile in
// this build is the same value; validate_proposals.go, validate_commit.go and the cache all reach
// for it the same way, and NewGroup is the single place a caller's *profile is read at all. When
// p8 lands a Profile that actually carries state, that swap is a package-wide one and these are
// two more of its call sites.

// ProposeAdd proposes that the client holding keyPackage join the group.
//
// The key package is judged HERE and not only at commit time. That is the difference between a
// caller learning that it fetched an expired, wrong-suite or wrongly signed package now, while it
// still has the directory it fetched from in hand, and learning it from a peer's refusal of a
// commit several steps later. Section 10.1's whole door is run rather than a version and suite
// comparison written out again in this file, so a package this build would refuse to ADMIT is one
// it also refuses to ADVERTISE.
//
// The clock is this client's own, for (*KeyPackage).Validate's stated reason: section 7.3 makes the
// lifetime a MUST for a leaf a client is about to admit, and this is the moment it is admitted.
//
// The v1 wrap target is required as well, and it is not part of section 10.1. Every commit this
// profile makes wraps the epoch's secret to urmessage_leaf_keys, so a joiner whose leaf carries
// none is a member no epoch can ever reach -- and the first symptom of admitting one is a member
// who cannot read anything, one commit after the commit that added them.
//
// NEITHER OF THOSE ASKS WHETHER THE GROUP ALREADY CARRIES THIS CLIENT'S KEYS, and that is not
// asked here either. Section 10.1 judges a key package against itself and a suite; ValSem101 and
// ValSem103 judge it against the members this group already has, and both of them are decidable
// off the pre-commit tree. They are asked once, for every generator, in (*Group).propose -- so
// what is left in this method is the part of an Add's judgement no list rule makes, and the part
// every list rule makes is not written out again here where a fourth generator would miss it.
func (self *Group) ProposeAdd(keyPackage []byte) ([]byte, error) {
	self.stateLock.Lock()
	crypto, suite, closed := self.crypto, self.context.CipherSuite, self.closed
	self.stateLock.Unlock()
	if closed {
		return nil, errGroupClosed
	}
	// decoded rather than taken as a structure, because what a peer will hash into the
	// KeyPackageRef and re-validate is these octets. syntax.Reader copies every opaque field it
	// reads, so the value below shares no array with the caller's buffer.
	var kp KeyPackage
	if err := syntax.Unmarshal(keyPackage, &kp); err != nil {
		return nil, err
	}
	if err := kp.Validate(crypto, suite, time.Now()); err != nil {
		return nil, err
	}
	if _, err := LeafKeysOf(&kp.LeafNode); err != nil {
		return nil, err
	}
	return self.propose(&Proposal{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: kp}})
}

// ProposeRemove proposes removing a leaf.
//
// REMOVING OUR OWN LEAF IS REFUSED, and the reason is what this method does with the proposal
// rather than anything RFC 9420 forbids. Section 12.1.3's leave flow IS a member sending a Remove
// for its own leaf and another member committing it, so the proposal itself is legitimate; what is
// not legitimate is this client CACHING one. Every proposal generated here is stored in this
// epoch's cache, and task 13's commit generation commits what the cache holds -- so a self remove
// sitting in it is a proposal this client's own next commit would carry, and
// validateCommitterIsNotRemoved refuses exactly that at every receiver. This plan has no leave
// flow to hand such a proposal to instead, so the refusal is here and the gap is named rather than
// left as a proposal that poisons the next commit.
//
// A leaf that is blank or outside the tree is ValSem108's refusal, asked at generation time under
// ValSem108's own value: a caller that named a member who has already been removed learns it from
// the call it made rather than from a commit nobody accepts.
func (self *Group) ProposeRemove(leaf LeafIndex) ([]byte, error) {
	self.stateLock.Lock()
	own, closed := self.ownLeaf, self.closed
	occupied := self.tree.Leaf(leaf) != nil
	self.stateLock.Unlock()
	if closed {
		return nil, errGroupClosed
	}
	if leaf == own {
		return nil, fmt.Errorf("%w: leaf %d is this client's own and a cached self remove is one this client's next commit would carry",
			ErrRemoveCommitter, leaf)
	}
	// REDUNDANT WITH THE DOOR (*Group).propose NOW RUNS, AND KEPT, on ValidateProposalList's own
	// stated terms and measured the same way: ValSem108 answers this condition the same value off
	// the same tree, so deleting this line leaves the whole of ./mls/... and ./message/... green.
	// It stays because it is asked before the lock and before anything is signed, and because the
	// asymmetry it used to be the only half of -- this generator asking its receivers' question
	// while ProposeAdd did not -- is what that door was written for. Nothing here claims a test
	// can tell which of the two guards fired.
	if !occupied {
		return nil, fmt.Errorf("%w: leaf %d", ErrRemoveNonMember, leaf)
	}
	return self.propose(&Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: leaf}})
}

// ProposeUpdate proposes replacing our own leaf with one holding a FRESH encryption key.
//
// THE FRESH KEY IS THE ENTIRE POINT OF THE PROPOSAL. An update that republished the key it
// replaces would be accepted by everything structural about it -- the leaf validates, the signature
// verifies, the tree still hashes -- and would provide no post compromise security at all, which is
// the only thing an Update buys. Section 12.1.2 states it as a rule and this package answers it
// with ErrUpdateEncryptionKeyUnchanged on the receive side; the draw below is the send side of the
// same rule, and TestProposeUpdateDrawsItsEncryptionKeyFreshAndFromItsOwnDraw is what holds it, by
// finding the published key again in the draws the provider was asked for rather than by asserting
// over this line.
//
// THE LEAF IS BUILT HERE AND NOT THROUGH NewLeafNode, which mints the key_package variant. That
// constructor fills in a Lifetime section 7.2's update arm does not carry and signs over a
// LeafNodeTBS that excludes the group id and the leaf index, so its answer would have to be mutated
// and re-signed anyway -- and a Lifetime left standing under a source whose encoding drops it is a
// field the Go value carries and no peer ever sees. This is testUpdateLeafNodeNaming's shape, which
// is the fixture every update this package validates is built from, and the Clone before the
// signature is NewLeafNode's own discipline: a leaf that goes on sharing an array with anything is
// a leaf that can change after it was signed.
//
// The device wrap key is read off the leaf being REPLACED and re-encoded, so an update publishes
// the same urmessage_leaf_keys the group already wraps to. A member whose update quietly changed it
// is a member the next commit wraps to a key it does not hold.
func (self *Group) ProposeUpdate() ([]byte, error) {
	var crypto CryptoProvider
	var signer SignaturePrivateKey
	var cred Credential
	var groupId []byte
	var at LeafIndex
	var leafKeysExt Extension
	var store StateStore
	if err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return errGroupClosed
		}
		current := self.tree.Leaf(self.ownLeaf)
		if current == nil {
			return fmt.Errorf("%w: this group holds no leaf at its own index %d",
				ErrTreeMalformed, self.ownLeaf)
		}
		keys, err := LeafKeysOf(current)
		if err != nil {
			return err
		}
		// re-encoded through the extension's own Encode, which answers the tag and the body
		// together and answers them as FRESH storage. The parse above hands back a body cut from
		// the tree's own extension, and a replacement leaf carrying that array would be a leaf
		// with a window onto the ratchet tree this epoch's tree hash was taken over.
		encoded, err := keys.Encode()
		if err != nil {
			return err
		}
		crypto, signer, at, store = self.crypto, self.signer, self.ownLeaf, self.store
		// the identity is copied for the leaf's sake and not the group's: everything below runs
		// outside this lock, and the credential is about to be signed over.
		cred = Credential{
			CredentialType: self.cred.CredentialType,
			Identity:       cloneBytes(self.cred.Identity),
		}
		groupId = cloneBytes(self.context.GroupId)
		leafKeysExt = encoded
		return nil
	}(); err != nil {
		return nil, err
	}

	signatureKey, err := signaturePublicKeyOf(signer)
	if err != nil {
		return nil, err
	}
	// the key pair this proposal exists to publish. Its own draw and its own DeriveKeyPair, for
	// NewKeyPackage's reason: one draw feeding two derivations answers two identical key pairs and
	// nothing about the value that comes back says so.
	encPriv, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		return nil, err
	}
	leaf := (&LeafNode{
		EncryptionKey:  encPub,
		SignatureKey:   signatureKey,
		Credential:     cred,
		Capabilities:   v1Capabilities(),
		LeafNodeSource: LeafNodeSourceUpdate,
		Extensions:     []Extension{leafKeysExt},
	}).Clone()
	// the group id and the leaf index are what section 7.2's update arm binds and the key_package
	// arm does not, so an update leaf signed with nil and 0 verifies against itself and against no
	// receiver -- see (*LeafNode).signatureContent.
	if err := leaf.Sign(crypto, signer, groupId, at); err != nil {
		return nil, err
	}
	// one verify, for NewLeafNode's reason: a provider whose signing half and verifying half
	// disagree, or a preimage that cannot be rebuilt from what was just written, is a leaf every
	// peer refuses and nothing in the value that comes back says so.
	if err := leaf.VerifySignature(crypto, groupId, at); err != nil {
		return nil, err
	}
	// THE PRIVATE HALF IS FILED BEFORE THE PROPOSAL IS PUBLISHED, and that order is the only one
	// that cannot lose it. A client that published an update and then failed to store the key
	// would be committed into an epoch whose own leaf key it does not hold, by a committer acting
	// entirely correctly on what it was sent. The pair is copied on the way out because the store
	// is an object the caller supplies and keeps what it is handed.
	if err := store.PutPrivateKey(cloneBytes(encPub), cloneBytes(encPriv)); err != nil {
		return nil, err
	}
	return self.propose(&Proposal{ProposalType: ProposalTypeUpdate, Update: &Update{LeafNode: *leaf}})
}

// ProposeGroupContextExtensions proposes replacing the group context's extension list wholesale.
//
// WHOLESALE IS THE RFC'S SEMANTICS AND NOT THIS METHOD'S CHOICE: section 12.1.6's proposal carries
// an extensions vector that REPLACES the group's, so a caller that means to add one extension
// passes the group's current list with the new entry in it. A caller that passes only the new entry
// drops the policy, which is what GroupPolicyOf refuses below.
//
// Every entry is judged before the proposal is built, so a policy violation never reaches the wire:
// checkGroupExtension is the same derived gate ValSem209 asks of a commit that installs one, so
// this build cannot propose an extension set it would itself refuse to install. GroupPolicyOf is
// the second door and it is this profile's rather than the RFC's -- a group here always carries a
// policy, and an extension set with none is a group with no owner and no roles, which nothing
// downstream would report until the first message that needed one.
func (self *Group) ProposeGroupContextExtensions(exts []Extension) ([]byte, error) {
	self.stateLock.Lock()
	closed := self.closed
	self.stateLock.Unlock()
	if closed {
		return nil, errGroupClosed
	}
	// THE CALLER'S ENTRIES ARE JUDGED AND FORWARDED AS THEY ARE, AND NOT COPIED HERE, which is the
	// opposite of NewGroup's rule at the other end of the same list and is opposite for the reason
	// that rule is stated over: RETENTION. NewGroup copies because the group's context KEEPS what
	// it was handed for the whole life of the group. Nothing below keeps anything -- the entries
	// are read into a preimage that is signed, into a message that is sealed and encoded, and into
	// the proposal cache, which makes its OWN copy through the codec because it is the thing that
	// outlives the call.
	//
	// A copy here as well would be two copies each covering for the other, which is the shape
	// proposal_list.go's own header rejects over its two map initialisations: neither line is one
	// any test can observe, and the one really doing the work stops being obvious. Measured, not
	// argued -- with the copy in place, deleting the CACHE's clone left this side green, and with
	// the copy gone TestTheProposalThisGroupCachesSharesNoStorageWithItsCaller fails on it.
	proposed := exts
	active := defaultProfile()
	for i := range proposed {
		if err := active.checkGroupExtension(proposed[i].ExtensionType); err != nil {
			return nil, fmt.Errorf("%w: at group_context_extensions entry %d", err, i)
		}
	}
	if _, err := GroupPolicyOf(proposed); err != nil {
		return nil, err
	}
	// AND THE REQUIRED CAPABILITIES BODY, READ THROUGH THE SAME LOOKUP ValSem209 READS IT THROUGH.
	// This is not a second policy check: it is the one extension of the installed set that the
	// receiving side reads BY TYPE, and reading it here is what makes a set carrying two of them a
	// refusal at generation rather than a choice the committer gets to make. Without it this
	// generator publishes a proposal ValSem209 refuses -- measured, by the probe in
	// extension_lookup_test.go's row for this method, which is the shape this whole section is
	// built to prevent.
	//
	// What is NOT asked here is ValSem209's other half, whether every member the commit LEAVES in
	// the group supports what the new set requires. That question is the commit's rather than the
	// proposal's: which members remain depends on the removes the same commit carries, and none of
	// them exist yet.
	if _, err := requiredCapabilitiesOf(proposed); err != nil {
		return nil, err
	}
	return self.propose(&Proposal{
		ProposalType:           ProposalTypeGroupContextExtensions,
		GroupContextExtensions: &GroupContextExtensions{Extensions: proposed},
	})
}

// propose frames, signs, protects, caches and encodes one proposal.
//
// The group context crosses into the framing layer as BYTES: FramedContentTBS inlines it with no
// length prefix of its own, and handing over the serialized form is what makes that impossible to
// get wrong here.
//
// The group id in the FramedContent is a COPY of the group's and not the group's, which is
// (*Group).persist's rule one call further out. sealPrivateMessage carries content.GroupId straight
// into the PrivateMessage header it builds, so a content assembled over the live slice would put
// the octets every epoch secret of this group was derived over into a structure this method hands
// to an encoder.
//
// IT IS A MEASURED SURVIVOR AND IT STAYS, which is worth writing down rather than leaving for the
// next reader to rediscover. Deleting the clone leaves the whole of ./mls/... and ./message/...
// green: the PrivateMessage that receives it is marshalled and dropped inside this call, and a
// CachedProposal holds a proposal and a sender and no group id, so nothing on this path retains it
// today. It is NOT the shape the extension copy in ProposeGroupContextExtensions was -- that one
// was a second copy standing beside the cache's, which was doing the work, and deleting the cache's
// is what a test could see. This is the only copy on this path, so the property is held by this
// line or by nobody, and what it guards is the one value every epoch secret of this group was
// derived over.
//
// THE CACHE IS WRITTEN LAST, AND THE ORDER IS INVERTED FROM THE PLAN'S ON PURPOSE. Stored first,
// every failure after it -- the seal, the encode -- leaves the cache holding a proposal no peer
// ever received, which task 13's commit generation then names in a commit every receiver refuses
// with "proposal reference is not cached for this epoch". The caller is told the propose failed and
// the group has quietly disagreed with it. Stored last, the only cost of a refusal is a generation
// of this leaf's own handshake ratchet spent on a message that was never returned, which every
// receiver already tolerates: generations are consumed by the sender and gaps are ordinary.
// Cheap and invisible on one side, silent divergence on the other, so the cheap failure is the one
// this takes.
//
// *SecretTree is passed where the framing layer declares a MessageKeySource; framing_protect.go
// carries the var _ MessageKeySource = (*SecretTree)(nil) assertion, so a drift between the two
// fails at build rather than at the first message.
//
// The compiler directive is the package's convention for a member of the class
// TestEveryEraseHelperCarriesTheNoInlineDirective derives, and it is not a claim that this body
// erases a secret. That class is "writes through storage that outlives the call", read off the
// source; this writes into the receiver's own proposal cache, which is the shape, and
// (*ProposalCache).Store carries the directive under the same reading and says so.
//
//go:noinline
func (self *Group) propose(proposal *Proposal) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, errGroupClosed
	}
	// before a single octet is signed, for (*Proposal).checkArm's reason one layer down: what is
	// signed here is a serialized form, and a caller that ignored an error out of the encoder must
	// not be able to walk away with a signature over a proposal that does not exist.
	//
	// REDUNDANT WITH THE CACHE'S OWN CALL AND KEPT, on ValidateProposalList's stated terms and
	// measured the same way: (*ProposalCache).Store runs checkProposalProfile too, so deleting this
	// line leaves the whole of ./mls/... and ./message/... green. It stays because the cache runs
	// LAST here -- see the ordering note above -- so without it a proposal outside the v1 profile is
	// signed, sealed and encoded, and a generation of this leaf's ratchet is spent, before anything
	// refuses it. Nothing here claims a test can tell which of the two guards fired.
	if err := checkProposalProfile(defaultProfile(), proposal); err != nil {
		return nil, err
	}
	// AND THROUGH THE DOOR EVERY RECEIVER WILL JUDGE IT AT, over a list holding this one proposal.
	//
	// THE OBLIGATION IS DERIVED HERE RATHER THAN RESTATED IN EACH GENERATOR, and that is the
	// difference between this and the two checks it makes unnecessary. ProposeAdd ran kp.Validate
	// and LeafKeysOf and nothing else, so an Add republishing a signature key this group already
	// carries was accepted, signed, sealed and CACHED -- while ValidateProposalList refuses that
	// same entry as a ONE ENTRY list, which is what says it was never a cross-proposal question
	// for the committer to answer. ValSem101 and ValSem103 each read their members' half off
	// in.Tree.NonBlankLeaves, which is this group's own pre-commit tree and is sitting under this
	// lock; ValSem105, ValSem106 and section 12.1.2's two rules on an Update's leaf are the same
	// shape. A fifth generator written later is inside this by existing, which a third hand
	// written check beside the other two would not have been.
	//
	// THE COMMITTER IS A LEAF INDEX OUTSIDE THIS TREE, and it is the one thing this reading cannot
	// decide. Exactly two rules of section 12.2 are stated over the committer -- ValSem111
	// compares it against an Update's sender, validateCommitterIsNotRemoved against a Remove's
	// target -- and nobody knows yet who will commit this. A leaf beyond the tree's width is named
	// by no proposal a member can send over this tree, so those two rules are left to the
	// committer and every other rule is asked now. That is what "the cross-proposal rules are the
	// committer's" was always meant to cover, and a one entry list is not it.
	//
	// It runs BEFORE the signature for the reason the profile gate above does: a refusal here
	// costs nothing, and the same refusal after the seal has already spent a generation of this
	// leaf's ratchet on a message no peer will ever be sent.
	if err := ValidateProposalList(&ProposalValidationInput{
		Crypto:    self.crypto,
		Tree:      self.tree,
		Context:   self.context,
		Committer: LeafIndex(self.tree.LeafWidth()),
		List: NewProposalList([]CachedProposal{
			{Proposal: *proposal, Sender: self.ownLeaf}}),
		Now: time.Now(),
	}); err != nil {
		return nil, err
	}
	groupContext, err := syntax.Marshal(self.context)
	if err != nil {
		return nil, err
	}
	content := &FramedContent{
		GroupId:     cloneBytes(self.context.GroupId),
		Epoch:       self.context.Epoch,
		Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: self.ownLeaf},
		ContentType: ContentTypeProposal,
		Proposal:    proposal,
	}
	authenticated, err := SignAuthenticatedContent(self.crypto, self.signer,
		WireFormatPrivateMessage, content, groupContext)
	if err != nil {
		return nil, err
	}
	// A-ASSUME-4: handshake traffic travels as a PrivateMessage, so the transport learns neither
	// which member proposed nor what was proposed.
	private, err := SealPrivateMessage(self.crypto, self.secretTree,
		self.senderDataSecretLocked(), authenticated, PaddingSizeV1)
	if err != nil {
		return nil, err
	}
	encoded, err := MarshalMLSMessage(&MLSMessage{
		Version:        ProtocolVersionMls10,
		WireFormat:     WireFormatPrivateMessage,
		PrivateMessage: private,
	})
	if err != nil {
		return nil, err
	}
	// the cache is handed the AuthenticatedContent and not the Proposal, because the reference an
	// entry is keyed by is a hash over the framed, signed content -- which is what a receiver of
	// the octets above will compute for the same message. A cache keyed by anything else holds
	// entries no commit of this group could name.
	if _, err := self.proposals.Store(self.crypto, self.context, authenticated); err != nil {
		return nil, err
	}
	return encoded, nil
}

// ---------------------------------------------------------------------------
// RFC 9420 section 12.4.1: commit generation
// ---------------------------------------------------------------------------

// THE ORDER OF THE STEPS BELOW IS THE RFC'S AND EVERY ONE OF THEM IS A DEPENDENCY.
//
// Section 12.4.1 reads as a list and could be mistaken for a checklist. It is not one: apply the
// proposals, then compute the update path, then the new epoch's secrets, then the confirmation tag
// over the new confirmed transcript hash. Each arrow is a value that does not exist until the step
// before it has run, and an implementation that took them in another order still produces 32 well
// formed octets at every stage:
//
//   - the update path's HPKE context is the NEW epoch's group context, whose tree_hash covers the
//     path's own public keys -- so the secrets are created (which installs those keys), THEN the
//     tree hash is taken, THEN the path is encrypted. That is why CreateUpdatePathSecrets and
//     EncryptUpdatePath are two calls and why no single CreateUpdatePath exists.
//   - the confirmed transcript hash is a function of the SIGNED commit, so the framing and the
//     signature come before it, and the new group context comes after.
//   - the confirmation tag is a MAC over the confirmed transcript hash OF THE EPOCH THIS COMMIT
//     OPENS. A tag taken over the epoch this commit closes is the same length, verifies against
//     nothing any receiver computes, and is what opts.confirmationTagOverPreCommitTranscript makes
//     on purpose.
//
// AND THE COMMIT IS STAGED RATHER THAN MERGED. The delivery service accepts at most one commit per
// (group, epoch), so a committer that advanced its own epoch here would fork itself off the group
// the moment somebody else's commit won that race (MASTER section 9.3). MergePendingCommit is what
// the acceptance calls.

// CreateCommit builds a commit over the named proposals and stages the epoch it opens.
//
// byReference is a slice of SERIALIZED ProposalRef values, so connect/message can name the
// proposals it saw on the wire without holding an mls type. Passing nil means "every valid proposal
// this client has cached for this epoch", which is RFC 9420 section 12.4's SHOULD; passing an empty
// non-nil slice means "none of them", and the two are deliberately different.
//
// byValue and opts.ExtraProposals are appended after the by-reference entries, in that order, and
// both are attributed to the committer -- which is what (*ProposalCache).Resolve does with a
// by-value entry and what makes ValSem111 decidable about them.
//
// THE COMMIT'S OWN VECTOR IS TAKEN FROM THE RESOLVED LIST AND NOT FROM THE ARGUMENTS, which is the
// one structural decision in this body. ValidateCommit holds a commit's ProposalOrRef vector and the
// list resolved from it to each other field by field -- checkListResolvesTheCommitsVector -- and a
// generator that built the two from two sources would be a generator whose commit can disagree with
// its own list. (*ProposalList).Refs rebuilds the vector from the list, so the two are one value
// here by construction rather than by a comparison this file would have to keep passing. It also
// settles the aliasing question for the by-value arm at the same time: the list's proposals were
// copied through the codec by Resolve, so nothing the commit carries is storage its caller still
// holds.
func (self *Group) CreateCommit(byReference [][]byte, byValue []Proposal, opts *CommitOptions) (*CommitResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, errGroupClosed
	}
	// before anything is resolved. A second staged commit would be a client holding two candidate
	// epochs with nothing to say which of them the delivery service accepted, and the repair --
	// ClearPendingCommit -- is a decision the caller makes rather than one this method can.
	if self.pending != nil {
		return nil, ErrPendingCommitExists
	}
	if opts == nil {
		opts = &CommitOptions{}
	}

	// step 1: name the proposals.
	//
	// The references are CLONED on the way in, for the reason the group id is cloned on the way
	// out of GroupId(): these octets go into the commit's own vector, which this group keeps on
	// the staged commit and which the confirmed transcript hash covers, so a caller that went on
	// writing into the buffer it named a proposal out of would be rewriting a commit that has
	// already been signed.
	refs := []ProposalOrRef{}
	if byReference == nil {
		refs = append(refs, self.proposals.Pending(self.context)...)
	} else {
		for _, ref := range byReference {
			refs = append(refs, ProposalOrRef{
				Type:      ProposalOrRefTypeReference,
				Reference: ProposalRef(cloneBytes(ref)),
			})
		}
	}
	for i := range byValue {
		proposal := byValue[i]
		refs = append(refs, ProposalOrRef{Type: ProposalOrRefTypeProposal, Proposal: &proposal})
	}
	for i := range opts.ExtraProposals {
		proposal := opts.ExtraProposals[i]
		refs = append(refs, ProposalOrRef{Type: ProposalOrRefTypeProposal, Proposal: &proposal})
	}
	list, err := self.proposals.Resolve(self.crypto, self.context, self.ownLeaf, refs)
	if err != nil {
		return nil, err
	}
	commit := &Commit{Proposals: list.Refs()}

	// step 2: apply the list to a tree of this call's own, and judge it against the pre-commit
	// state. ApplyProposals clones, so self.tree is untouched however this call ends.
	applied, err := ApplyProposals(self.tree, self.context, self.ownLeaf, list)
	if err != nil {
		return nil, err
	}
	if !opts.skipValidation {
		if err := ValidateProposalList(&ProposalValidationInput{
			Crypto:     self.crypto,
			Tree:       self.tree,
			Context:    self.context,
			Extensions: applied.Extensions,
			Committer:  self.ownLeaf,
			List:       list,
			Now:        time.Now(),
		}); err != nil {
			return nil, err
		}
		// AND THIS PROFILE'S OWN THREE DOORS GO HERE, in this order, between section 12.2's
		// rules and the path: MASTER section 6's membership and device caps and section 8's
		// removal authority are task 20's, and section 11's owner succession is task 21's. All
		// three are decidable off `applied` and `list`, both of which are in hand at this point
		// and neither of which any later step can restate, and all three must run BEFORE the
		// path is built, because a refusal after CreateUpdatePathSecrets has drawn a leaf key
		// costs a key pair and a tree clone for a commit that was never going to be sent.
		//
		// THE PLAN LANDS THEM HERE AS STUBS AND THIS TASK DOES NOT, and that is a deliberate
		// deviation. A body that names its arguments, reads none of them and answers nil is the
		// shape TestNoStubShapesRemainInSource derives and refuses -- "a parameter the body never
		// reads, which is the plausible zero value" -- and the two spellings that get past it are
		// an underscore parameter, which the sealed storage scan refuses in its turn, and a
		// `_ = argument` line, which is that gate's own stated blind spot. A door that decides
		// nothing is not made safer by being written down; what the ordering needs is this
		// paragraph, and what the doors need is their tasks.
	}

	// step 3: the path, in the three ordered steps this file's header states.
	//
	// The provisional context carries the PREVIOUS epoch's confirmed transcript hash, because the
	// new one is a function of this very commit and this commit is not framed yet. That is not an
	// approximation: section 12.4.2 has every receiver decrypt the path under exactly this
	// context, so what matters is that the two sides build the same one.
	commitSecret := ZeroSecret(self.crypto)
	var plan *UpdatePathPlan
	hasPath := CommitPathRequired(list) || opts.Force
	// the tree a RECEIVER judges this commit against, kept apart from the one the epoch ends up
	// with. Section 12.4.2 applies the proposals, validates the path against THAT tree, and
	// merges the path afterwards, and the two trees are not interchangeable here: ValSem207
	// refuses a path publishing a key that already stands in the tree it is handed, so a
	// validator given the tree with the path already installed refuses every commit whose path
	// has a node in it -- which is every commit of a group with more than one member.
	// CreateUpdatePathSecrets mutates the tree it is called on, so the clone is taken first.
	postProposal := applied.Tree
	if hasPath {
		postProposal = applied.Tree.Clone()
		plan, err = applied.Tree.CreateUpdatePathSecrets(self.crypto, self.ownLeaf,
			self.signer, cloneBytes(self.context.GroupId))
		if err != nil {
			return nil, err
		}
		pathTreeHash, err := applied.Tree.TreeHash(self.crypto)
		if err != nil {
			return nil, err
		}
		provisional := &GroupContext{
			Version:                 self.context.Version,
			CipherSuite:             self.context.CipherSuite,
			GroupId:                 cloneBytes(self.context.GroupId),
			Epoch:                   self.context.Epoch + 1,
			TreeHash:                pathTreeHash,
			ConfirmedTranscriptHash: cloneBytes(self.context.ConfirmedTranscriptHash),
			Extensions:              applied.Extensions,
		}
		provisionalBytes, err := syntax.Marshal(provisional)
		if err != nil {
			return nil, err
		}
		// the members this commit ADDS are excluded: they receive the path secret in their
		// Welcome and must not also be sealed to here, where they hold no key yet.
		path, err := applied.Tree.EncryptUpdatePath(self.crypto, plan, self.ownLeaf,
			provisionalBytes, applied.AddedLeaves)
		if err != nil {
			return nil, err
		}
		commit.Path = path
		commitSecret = plan.CommitSecret
	}

	// step 4: frame and sign the commit against the OLD group context, because that is the epoch
	// every receiver is still in and the epoch its signature has to verify under.
	oldContextBytes, err := syntax.Marshal(self.context)
	if err != nil {
		return nil, err
	}
	content := &FramedContent{
		GroupId:     cloneBytes(self.context.GroupId),
		Epoch:       self.context.Epoch,
		Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: self.ownLeaf},
		ContentType: ContentTypeCommit,
		Commit:      commit,
	}
	authenticated, err := SignAuthenticatedContent(self.crypto, self.signer,
		WireFormatPrivateMessage, content, oldContextBytes)
	if err != nil {
		return nil, err
	}

	// step 5: the new transcript hashes, the new group context and the new key schedule.
	confirmedInput, err := authenticated.ConfirmedTranscriptHashInput()
	if err != nil {
		return nil, err
	}
	confirmedHash := ConfirmedTranscriptHash(self.crypto, self.transcript.Interim, confirmedInput)
	treeHash, err := applied.Tree.TreeHash(self.crypto)
	if err != nil {
		return nil, err
	}
	newContext := &GroupContext{
		Version:                 self.context.Version,
		CipherSuite:             self.context.CipherSuite,
		GroupId:                 cloneBytes(self.context.GroupId),
		Epoch:                   self.context.Epoch + 1,
		TreeHash:                treeHash,
		ConfirmedTranscriptHash: confirmedHash,
		Extensions:              applied.Extensions,
	}
	schedule, err := NewKeySchedule(self.crypto, self.schedule.Secrets().InitSecret, commitSecret,
		EmptyPskSecret(self.crypto), newContext)
	if err != nil {
		return nil, err
	}

	// step 6: the confirmation tag over the confirmed transcript hash OF THE EPOCH THIS COMMIT
	// OPENS, and then the interim hash from it.
	tagOver := confirmedHash
	if opts.confirmationTagOverPreCommitTranscript {
		tagOver = self.transcript.Confirmed
	}
	confirmationTag := schedule.ConfirmationTag(tagOver)
	// ConfirmationTag answers nil for an epoch whose confirmation_key has been erased. Nothing can
	// have erased this one -- the schedule was built four statements ago -- so this is a refusal
	// over a build that has stopped agreeing with itself, and it is made here for NewGroup's
	// reason: the alternative is folding a nil tag into the interim hash and staging an epoch
	// whose successor nobody can compute.
	if len(confirmationTag) != self.crypto.HashSize() {
		return nil, fmt.Errorf("%w: the schedule answered %d octets, want %d",
			errCommitConfirmationTag, len(confirmationTag), self.crypto.HashSize())
	}
	authenticated.Auth.ConfirmationTag = confirmationTag
	if opts.dropConfirmationTag {
		authenticated.Auth.ConfirmationTag = nil
	}
	// a CLONE of the transcript, so a refusal below leaves this group's own transcript where the
	// epoch it is still in put it.
	transcript := self.transcript.Clone()
	if err := transcript.Update(self.crypto, confirmedInput, confirmationTag); err != nil {
		return nil, err
	}

	// step 7: the commit this client is about to send, through the door every receiver of it will
	// judge it at.
	//
	// THE CONTEXT IS THE PRE-COMMIT ONE AND THE EXTENSIONS ARE THE POST-COMMIT SET, which is not a
	// muddle. Every rule of section 12.2 is stated over the group the proposals ARRIVED in, the
	// by-reference arm of the vector join resolves each reference against this member's cache --
	// which is bound to the epoch that is closing -- and effectiveExtensions is the field that
	// carries the post-proposal set to the rules that need it. A newContext here answers
	// errProposalNotCached for every commit that names a proposal by reference, which is every
	// commit a real group produces.
	//
	// CheckErrata8745 and CheckErrata8815 are NOT called beside this. ValidateCommit reaches both
	// through validateCommitErrata, so a second call here would be a second transcription of two
	// rules whose whole point is that there is one of each.
	if !opts.skipValidation {
		commitInput := &CommitValidationInput{
			Crypto:          self.crypto,
			PreTree:         self.tree,
			PostTree:        postProposal,
			Context:         self.context,
			Extensions:      applied.Extensions,
			Committer:       self.ownLeaf,
			Own:             self.ownLeaf,
			List:            list,
			Commit:          commit,
			Pending:         self.proposals,
			ConfirmationKey: schedule.Secrets().Confirmation,
			ConfirmedHash:   confirmedHash,
			ConfirmationTag: authenticated.Auth.ConfirmationTag,
			Now:             time.Now(),
		}
		if err := ValidateCommit(commitInput); err != nil {
			return nil, err
		}
		// ValSem205 is not in ValidateCommit's own list and its own comment says why: the
		// confirmation key belongs to the epoch this commit OPENS, so it does not exist until
		// the schedule above has been derived. The caller that has one runs it, and this is
		// that caller.
		if err := ValSem205ConfirmationTag(commitInput); err != nil {
			return nil, err
		}
	}

	// step 8: the new epoch's verified context, which is what the boundary owes the proposal
	// cache. The creator earns one the same way at epoch 0 -- see NewGroup -- and it is earned
	// HERE rather than at the merge so that every refusal this commit can make is made before a
	// generation of this leaf's message ratchet has been spent on it.
	groupInfo := &GroupInfo{
		GroupContext:    *newContext,
		ConfirmationTag: confirmationTag,
		Signer:          self.ownLeaf,
	}
	if err := groupInfo.Sign(self.crypto, self.signer); err != nil {
		return nil, err
	}
	verified, err := groupInfo.VerifiedContext(self.crypto, applied.Tree)
	if err != nil {
		return nil, err
	}
	secretTree, err := NewSecretTree(self.crypto, applied.Tree.LeafWidth(),
		schedule.Secrets().Encryption)
	if err != nil {
		return nil, err
	}

	// step 9: protect the commit under the OLD epoch's keys and put it on the wire. A-ASSUME-4:
	// handshake traffic travels as a PrivateMessage, so the transport learns neither who committed
	// nor what the commit did.
	//
	// LAST, because it is the first thing here that cannot be undone: the seal consumes a
	// generation of this leaf's ratchet whether or not the commit is ever sent.
	private, err := SealPrivateMessage(self.crypto, self.secretTree,
		self.senderDataSecretLocked(), authenticated, PaddingSizeV1)
	if err != nil {
		return nil, err
	}
	commitMessage, err := MarshalMLSMessage(&MLSMessage{
		Version:        ProtocolVersionMls10,
		WireFormat:     WireFormatPrivateMessage,
		PrivateMessage: private,
	})
	if err != nil {
		return nil, err
	}
	encodedTree, err := syntax.MarshalLimit(applied.Tree, syntax.MaxRatchetTreeLength)
	if err != nil {
		return nil, err
	}

	// a commit with no path leaves this client's own leaf key where it was, so the private state
	// carries forward; a commit with one replaces it, and the plan's private half is that
	// replacement.
	ownPriv := self.ownPriv
	if plan != nil && plan.Private != nil {
		ownPriv = plan.Private
	}
	staged := &StagedCommit{
		committer:   self.ownLeaf,
		epoch:       newContext.Epoch,
		context:     newContext,
		verified:    verified,
		tree:        applied.Tree,
		schedule:    schedule,
		secretTree:  secretTree,
		ownPriv:     ownPriv,
		transcript:  transcript,
		list:        list,
		commit:      commit,
		added:       applied.AddedLeaves,
		removed:     applied.RemovedLeaves,
		updated:     applied.UpdatedLeaves,
		selfRemoved: applied.SelfRemoved,
		hasPath:     hasPath,
		confirmTag:  confirmationTag,
		plan:        plan,
		restoreKind: restoreFromJoiner,
	}
	self.pending = staged

	// AND THE WELCOME FOR THE MEMBERS THIS COMMIT ADDS IS TASK 15'S, so a commit covering an Add
	// answers none today. That is a HOLE and not a design: the added member has a leaf in the tree
	// this result publishes and no way to reach the epoch, and
	// TestACommitCoveringAnAddCarriesNoWelcomeUntilTask15 is what makes it impossible to forget --
	// it fails on the commit that starts building one, rather than waiting for somebody to
	// remember. Task 15 assembles it from `staged`, which carries the new epoch's schedule, the
	// post-commit tree and the leaves the adds landed on.
	return &CommitResult{Commit: commitMessage, RatchetTree: encodedTree}, nil
}

// ClearPendingCommit discards a staged commit. It is what a caller calls when the delivery service
// accepted somebody ELSE's commit for this epoch (MASTER section 9.3, spec A section 5.12): the
// staged epoch is then an epoch nobody entered, and the group has to be able to build another
// commit against the epoch it is still in.
//
// It answers nothing, because there is no failure here to report: clearing a commit that was never
// staged is the same state as clearing one that was.
func (self *Group) ClearPendingCommit() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pending = nil
}

// MergePendingCommit promotes the staged commit to live state. Task 19 adds the persistence and the
// past-epoch window; what is here is the state swap and the boundary the cache is owed.
//
// THE CACHE IS REBOUND TO THE EPOCH THE GROUP MOVED TO, on every path out of this method, and that
// is the whole of what an epoch boundary owes it. A cache left behind belongs to the epoch that just
// closed and every reference in it names a proposal this commit has already applied; a cache
// rebound to that same closing epoch is worse, because it then refuses every proposal of the new
// epoch as well and nothing in this package releases it.
func (self *Group) MergePendingCommit() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.pending == nil {
		return ErrNoPendingCommit
	}
	staged := self.pending
	// the rebind runs BEFORE nothing and AFTER the write, which is the order the boundary is
	// stated in: the cache takes its epoch from the context the group has moved to, and a rebind
	// written ahead of the move would hand it the epoch that is closing.
	self.tree = staged.tree
	self.context = staged.context
	self.verified = staged.verified
	self.schedule = staged.schedule
	self.secretTree = staged.secretTree
	self.ownPriv = staged.ownPriv
	self.transcript = staged.transcript
	self.restoreKind = staged.restoreKind
	if err := self.proposals.Rebind(staged.verified); err != nil {
		return err
	}
	self.pending = nil
	return nil
}

