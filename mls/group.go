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
	"crypto/subtle"
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

	// the Welcome half of a commit, and two values because they are two faults a caller
	// repairs differently.
	//
	// errWelcomeAddPairing is the ONE ASSUMPTION (*StagedCommit).welcomeMessage rests on, written as a
	// refusal rather than left as an index: StagedCommit.added and (*ProposalList).Adds are two
	// readings of the same Add proposals -- ApplyProposals walks the commit order and appends a
	// leaf per Add, and Adds is that same order filtered -- so entry i of one is entry i of the
	// other. A build where they part company would seal each joiner's group secrets to some
	// OTHER joiner's init key, silently, with every length equal and every seal well formed.
	// The proposal list was rebuilt around one representation precisely because a COUNT is what
	// a dual representation gets held together by and a count is what let four forks through, so
	// this is stated where the pairing is used rather than assumed at a distance.
	errWelcomeAddPairing = errors.New(
		"mls: the leaves this commit added and the Add proposals it names are not the same list")

	// errWelcomePathSecret is a commit that carried an update path and cannot say where one of
	// its joiners picks that path up.
	//
	// A refusal and not a nil path secret, which is the whole reason it exists. GroupSecrets
	// carries an optional<PathSecret>, so "absent" is a MEANING a joiner acts on -- seed your
	// direct path from the tree as it stands -- and a commit that reset the nodes above the
	// joiner while telling it nothing was reset produces a member that derives the wrong key for
	// every node it shares with the committer, at the far end, with nothing here to point at.
	errWelcomePathSecret = errors.New(
		"mls: this commit carried an update path and holds no path secret for a joiner")
	// and the RECEIVING half, task 16. One value per rule for this block's stated reason; what
	// each of them means is written on JoinFromWelcome beside the step that answers it.
	//
	// errNilJoinKeyMaterial is a join with nothing to join AS. It is separate from
	// errNilGroupConfig because the two are different missing objects with different repairs, and
	// a caller told "there is no group config" while holding one would go looking at the wrong
	// argument.
	errNilJoinKeyMaterial = errors.New("mls: there is no key material for this joiner to join with")

	// errWelcomeWireFormat is a message handed to the joiner that is not a Welcome. It is not
	// ErrWelcomeSuiteMismatch or any other welcome refusal: nothing about a Welcome has been
	// judged, because the thing in hand is not one.
	errWelcomeWireFormat = errors.New("mls: the message handed to this joiner is not a welcome")

	// errWelcomeJoinerProviderSuite is a Welcome naming one ciphersuite in the clear while the
	// provider this joiner runs is another. It is NOT ErrWelcomeSuiteMismatch, which is the
	// welcome against the joiner's own key package, and it is not welcome.go's
	// errWelcomeSuiteProvider, which is the same disagreement at the BUILDING end -- three pairs
	// of values, and a caller sent to look at the wrong pair looks at two values that agree.
	errWelcomeJoinerProviderSuite = errors.New(
		"mls: the welcome names a ciphersuite the provider joining under it does not run")

	// errWelcomeGroupSecretsDecrypt is the entry addressed to this joiner's key package failing to
	// open under this joiner's init key.
	//
	// A SEPARATE VALUE FROM ErrWelcomeNoMatchingKeyPackage, and the split is the pairing. That one
	// is "no entry here is addressed to me", which is an ordinary condition -- a Welcome for a
	// commit that added somebody else. This one is "the entry that NAMES me was not sealed to me",
	// which is a Welcome whose reference half and whose seal half disagree: an entry lifted off
	// another Welcome, a seal made to another joiner's init key, or a builder that paired joiner
	// i's reference with joiner j's ciphertext. Collapsing the two would let a test asserting the
	// ordinary condition pass over the forgery.
	errWelcomeGroupSecretsDecrypt = errors.New(
		"mls: the group secrets addressed to this joiner did not open under its init key")

	// errWelcomeGroupIdNotTheOneAsked is a Welcome describing a group other than the one the
	// caller's config named. See JoinFromWelcome: it is an intent match and not authentication,
	// and it is its own value so that a caller can tell "this is not the group I asked for" from
	// every cryptographic refusal beside it.
	errWelcomeGroupIdNotTheOneAsked = errors.New(
		"mls: the welcome describes a group other than the one this client asked to join")

	// errWelcomeLeafNotTheJoiners is a tree carrying this joiner's signature key at a leaf that is
	// not the leaf its key package published.
	//
	// NOT ErrWelcomeLeafNotFound, which is "no leaf of this tree is mine". This one is "a leaf of
	// this tree claims to be mine and is not", which is the substitution the whole check exists
	// for, and a single value would let a test asserting the absence pass over it.
	errWelcomeLeafNotTheJoiners = errors.New(
		"mls: the tree's leaf for this joiner is not the leaf its key package published")

	// errJoinerSignatureKeyNotTheLeafs is a joiner whose signing key is not the signature key its
	// own key package published.
	//
	// The two halves arrive at this door independently -- the key package out of whatever the
	// caller stored, the private half out of the device's own keyring -- and this is the one door
	// of the three that produces a leaf for this client where they are not one value: NewLeafNode
	// and (*Group).ProposeUpdate both DERIVE the published key from the private one through
	// signaturePublicKeyOf, so a mismatch there cannot be written. A joiner that installed the
	// mismatched pair signs every message it sends with a key its own published leaf does not
	// name; every other member refuses those messages at the signature, and neither end holds
	// anything that says why.
	errJoinerSignatureKeyNotTheLeafs = errors.New(
		"mls: this joiner's signing key is not the signature key its key package published")

	// errJoinerWelcomeSecret is this build disagreeing with itself about welcome_secret: the value
	// JoinFromWelcome derived to open the encrypted group info is not the one the key schedule
	// derives from the same joiner secret. Its whole account is at the comparison.
	errJoinerWelcomeSecret = errors.New(
		"mls: the welcome secret this joiner opened the group info with is not the one its key schedule derives")

	// errWelcomePathSecretNode is a Welcome handing this joiner a path secret for an epoch whose
	// update path never covered it: the lowest node the joiner and the sender share is not on the
	// sender's filtered direct path. It is the receiving half of errWelcomePathSecret above and a
	// separate value for that block's reason -- one is a commit that could not be built and this
	// is a message that cannot be believed.
	errWelcomePathSecretNode = errors.New(
		"mls: the welcome's path secret is for a node the sender's update path did not cover")
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
//
// IT NO LONGER ASKS ValSem300 OF THE IN-MEMORY TREE, which is the SECOND instance of the fault
// validateCommitPostTreeIsExportable was repaired for and is written here rather than left for the
// next reader to find. Section 12.4.3.3's trailing blank rule is about the ARRAY this method
// EMITS, and MarshalMLS strips the trailing blanks as it writes; an in-memory tree is held at the
// full width 2^(d+1)-1, so a group whose size is not a power of two ends in blank nodes the moment
// an Add extends its tree. Measured: with the rule asked here, a three member group could not
// publish its own tree -- and there was no three member group in this build until commit generation
// landed, which is why the fixture corpus worked around it at 512 leaves rather than reporting it.
//
// AND NOTHING TAKES ITS PLACE, which is a decision rather than a hole. The one thing left to refuse
// about a tree at full width is an array with no non-blank node in it, and (*RatchetTree).MarshalMLS
// already refuses exactly that with ErrTreeMalformed on the line below -- so a guard here would be a
// second copy covering for the one really doing the work, which is the shape this file rejects in
// (*Group).ProposeGroupContextExtensions and which no input could tell apart from the encoder's own
// answer. validateCommitPostTreeIsExportable states that half itself because it encodes nothing.
func (self *Group) RatchetTree() ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
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
	// THE STAGED EPOCH IS ERASED TOO, and it was not until this line existed. A close that
	// dropped self.pending left a complete second epoch in the heap -- its own key schedule, its
	// own secret tree, and the leaf private key this client drew for the epoch its commit would
	// have opened -- held by nothing that erases it, which is exactly the discipline
	// StagedCommit's own comment invokes and was not taking.
	self.pending.Zeroize()
	// and this epoch's own leaf private state and signing key, which are storage this group
	// DECLARES rather than storage it points at. Both are copies this group made -- NewGroup
	// clones the caller's signing key and draws the leaf key itself -- so the erase reaches
	// nothing the caller is still holding.
	self.ownPriv.Zeroize()
	zeroizeSecret(self.signer)
	self.schedule = nil
	self.secretTree = nil
	self.pending = nil
	self.ownPriv = nil
	self.signer = nil
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
	// THE CALLER'S OCTETS ARE NOT COPIED HERE, and that is measured rather than assumed. Nothing
	// below retains this vector: it is read into (*ProposalCache).Resolve, which keys every
	// by-reference entry through `string(entry.Reference)` -- a conversion that copies -- and
	// copies every by-value proposal through the codec, and the commit's own vector is then built
	// from the RESOLVED list rather than from these entries. A clone here would be a second copy
	// covering for the one really doing the work, which is the shape
	// (*Group).ProposeGroupContextExtensions rejects at the other end of the same file: with the
	// clone in place, aliasing the caller's reference left the whole of ./mls/... and
	// ./message/... green, because there was no input that could tell the two programs apart.
	refs := []ProposalOrRef{}
	if byReference == nil {
		refs = append(refs, self.proposals.Pending(self.context)...)
	} else {
		for _, ref := range byReference {
			refs = append(refs, ProposalOrRef{
				Type:      ProposalOrRefTypeReference,
				Reference: ProposalRef(ref),
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
	// EVERY REFUSAL BELOW DROPS THE PLAN, and the plan is key material: this epoch's commit
	// secret, every path secret on the ladder, and the leaf private key this commit drew. There
	// are a dozen returns between the plan's construction and the staging that takes ownership of
	// it -- a seal that fails, a door that refuses, a GroupInfo this client cannot sign -- so the
	// erase is written once here rather than a dozen times, and the flag is what keeps it off the
	// one path where a StagedCommit took the plan and owes it an erase of its own.
	//
	// Private is erased HERE and not by (*UpdatePathPlan).Zeroize, for the reason that method's
	// own comment gives: on the path where the plan is handed on, its private half is the leaf
	// state the merge installs.
	handedOn := false
	defer func() {
		if handedOn || plan == nil {
			return
		}
		plan.Zeroize()
		plan.Private.Zeroize()
	}()
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
		// MEASURED, because a door that never fires reads like one that is not needed. Deleting
		// this call refuses no commit any test of this package builds -- section 12.2's rules are
		// already asked one block up, and this generator builds its own path correctly -- so the
		// only thing that reports its absence today is
		// TestEveryExportedRuleIsAppliedByThisPackageOrPinnedAsUnwired, which reads it as this
		// package shipping a commit validator its own construction does not run. What the call is
		// FOR is the class it was put here for, a generator handing its own door a tree the
		// receiver will not have, and that class has a measured instance: with `postProposal`
		// replaced by the tree the path has already been merged into, ValSem207 refuses the commit
		// HERE and nothing else in this package notices.
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
	//
	// THE CARRIED-FORWARD STATE IS CLONED AND NOT SHARED, which it was not before the staged
	// epoch was given an erase. A staged commit is erased when it is dropped -- ClearPendingCommit
	// on MASTER section 9.3's lost-commit race, and Close -- so a staged commit holding this
	// group's own live leaf private state would erase, on that ordinary path, the key the epoch
	// this group is still in opens its update paths with. It is the reason (*TreeKEMPrivate).Clone
	// exists at all, stated one caller further out.
	ownPriv := self.ownPriv
	if plan != nil && plan.Private != nil {
		ownPriv = plan.Private
	} else if ownPriv != nil {
		ownPriv = ownPriv.Clone()
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
	// step 10: the Welcome for the members this commit adds, built BEFORE the staged epoch is
	// installed as this group's pending commit.
	//
	// THAT ORDER IS THE REFUSAL'S. welcomeMessage can fail -- a joiner whose key package will
	// not encode, a commit that cannot say where a joiner picks up its path -- and a failure
	// after `self.pending = staged` would leave this group holding a staged epoch its caller was
	// never handed and does not know to clear, while answering that caller an error. So the
	// staged commit stays a local until the last thing that can fail has succeeded, and the one
	// path that drops it erases it: it is a complete second epoch -- a key schedule, a secret
	// tree and the leaf key this commit drew -- and after the return nothing in this process can
	// reach it.
	//
	// IT IS HANDED THE GROUP INFO STEP 8 ALREADY BUILT, SIGNED AND VERIFIED, rather than
	// assembling a second one. Two assemblies of one structure agree with each other for exactly
	// as long as their field lists happen to match, which is the defect welcome_wire.go's header
	// states and which this project has already paid for once on KeyPackage; and this way the
	// group info a joiner opens out of the Welcome is the very object VerifiedContext accepted
	// against the tree this result publishes, rather than a second one built to the same recipe.
	welcome, err := staged.welcomeMessage(self.crypto, groupInfo)
	if err != nil {
		staged.Zeroize()
		return nil, err
	}
	self.pending = staged
	handedOn = true

	return &CommitResult{
		Commit:      commitMessage,
		Welcome:     welcome,
		RatchetTree: encodedTree,
	}, nil
}

// welcomeMessage builds the Welcome for every member this commit added, or nil for a commit that
// added nobody.
//
// A METHOD ON THE STAGED COMMIT AND NOT ON THE GROUP, where the plan wrote it. Every
// field it reads is this commit's own -- the leaves the adds landed on, the proposal list they
// came from, the update path plan, the new epoch's key schedule and the committer's leaf -- so it
// touches no group state and needs nothing the epoch boundary has not already settled.
//
// The shape is also what keeps CreateCommit inside
// TestEveryCompositionEnteringALabelledConstructionIsBoundedBeforeItGetsThere, and that is
// measured rather than incidental. That gate taints a receiver the moment a composition is handed
// to a METHOD ON IT -- "a value handed to a method on a local is part of that local from here on"
// -- so the same body written as a GROUP method, called self.buildWelcome(staged, groupInfo),
// makes every later self.something() in CreateCommit carry the group info, and five of that
// function's own compositions were then reported as reaching a labelled construction through
// self.senderDataSecretLocked(). Written as a method on the value the bytes already belong to,
// the taint stays where it was.
//
// NIL AND NOT AN EMPTY WELCOME for the no-add case, because CommitResult.Welcome is documented as
// nil when the commit adds nobody and a caller branches on it: a Welcome sealed to an empty
// joiner set is a message a delivery service would carry to nobody, at the cost of one AEAD seal
// over the group info every time anybody commits anything.
//
// THE PATH SECRET EACH JOINER IS HANDED is the one for the LOWEST NODE ITS LEAF AND THE
// COMMITTER'S LEAF SHARE, RFC 9420 section 12.4.3.1. That node is on the committer's filtered
// direct path whenever the commit carries a path at all: its child on the joiner's side contains
// the joiner's leaf, which the proposals have already installed in the tree the plan was built
// over, so that child's resolution is non-empty and the node is not one the filter drops. It is
// also exactly the node the joiner is NOT sealed to in the update path itself -- CreateCommit
// excludes the added leaves from EncryptUpdatePath, because a member that holds no key yet cannot
// open anything -- so this secret and that exclusion are two halves of one decision.
//
// The secret is CLONED into the joiner entry rather than aliased off the plan. The entries are
// erased below the moment the seals are made, and an entry that aliased the plan's ladder would
// erase the committer's own path secrets as a side effect of building a message.
func (self *StagedCommit) welcomeMessage(crypto CryptoProvider, info *GroupInfo) ([]byte, error) {
	// the provider first, before anything is read off the receiver: every seal, expansion and
	// reference below is taken through it, and a caller that passed none is told that rather
	// than being answered "this commit added nobody", which is true of the zero value and is
	// not the fault it made.
	if crypto == nil {
		return nil, fmt.Errorf("%w: the welcome is sealed through it", ErrNilCryptoProvider)
	}
	if len(self.added) == 0 {
		return nil, nil
	}
	adds := self.list.Adds()
	if len(adds) != len(self.added) {
		return nil, fmt.Errorf("%w: %d leaf/leaves were added and %d Add proposal(s) are named",
			errWelcomeAddPairing, len(self.added), len(adds))
	}
	joiners := make([]WelcomeJoiner, 0, len(self.added))
	// the entries hold this epoch's path secrets, and they are this function's own copies, so
	// this function is the drop site that owes them an erase. The defer covers the refusals below
	// as well as the ordinary return: a Welcome that could not be built is still a Welcome whose
	// ladder was assembled.
	defer func() {
		for i := range joiners {
			joiners[i].Zeroize()
		}
	}()
	for i, leafIndex := range self.added {
		joiner := WelcomeJoiner{
			KeyPackage: adds[i].Proposal.Add.KeyPackage,
			LeafIndex:  leafIndex,
		}
		if self.plan != nil {
			ancestor := CommonAncestor(leafIndex.NodeIndex(), self.committer.NodeIndex())
			secret := pathSecretAt(self.plan, ancestor)
			if secret == nil {
				return nil, fmt.Errorf("%w: node %d is the lowest node leaf %d and leaf %d share",
					errWelcomePathSecret, ancestor, leafIndex, self.committer)
			}
			joiner.PathSecret = cloneBytes(secret)
		}
		joiners = append(joiners, joiner)
	}

	// the CLEARTEXT suite of the Welcome is the one the epoch this commit opens names, which is
	// the same suite the provider runs -- NewGroup refused any other pairing at creation and no
	// commit changes a group's ciphersuite. BuildWelcome refuses the disagreement rather than
	// trusting that sentence.
	welcome, err := BuildWelcome(crypto, self.context.CipherSuite, info,
		self.schedule.JoinerSecret(), self.schedule.WelcomeSecret(), joiners)
	if err != nil {
		return nil, err
	}
	return MarshalMLSMessage(&MLSMessage{
		Version:    ProtocolVersionMls10,
		WireFormat: WireFormatWelcome,
		Welcome:    welcome,
	})
}

// pathSecretAt is the plan's secret for one node, or nil for a node the plan does not cover.
//
// UpdatePathPlan.Path and UpdatePathPlan.PathSecrets are PARALLEL -- CreateUpdatePathSecrets
// builds one ladder rung per filtered node and slices the commit secret off the end -- so this is
// an index lookup into the structure that already exists rather than a second map of the same
// data kept beside it. A second map is the dual representation the proposal list was rebuilt to
// remove, at a smaller scale.
//
// Nil for a nil plan, for the same reason it answers nil for an unlisted node: "the secret for
// this node, if the commit has one" is the question every call site asks, and the caller that
// cannot proceed without one refuses on the nil rather than on a second guard here.
func pathSecretAt(plan *UpdatePathPlan, node NodeIndex) []byte {
	if plan == nil {
		return nil
	}
	for i, x := range plan.Path {
		if x == node && i < len(plan.PathSecrets) {
			return plan.PathSecrets[i]
		}
	}
	return nil
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
	// erased BEFORE it is dropped, and this is the ordinary path rather than a cleanup one: the
	// epoch being discarded is fully derived -- key schedule, secret tree and the leaf key drawn
	// for it -- and after the assignment below nothing in this process can reach it to erase it.
	self.pending.Zeroize()
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
	// THE EPOCH THIS MERGE CLOSES IS ERASED AS IT IS DROPPED. There is no past-epoch window in
	// this build -- task 19 adds one -- so the schedule, the secret tree and the leaf private
	// state this group holds at this instant become unreachable the moment the assignments below
	// land, and unreachable is not erased. What makes erasing them safe is that none of the three
	// is the value being installed: CreateCommit derives a fresh schedule and a fresh secret tree
	// for the staged epoch, and its leaf private state is either the update path plan's or a
	// CLONE of this one.
	if self.schedule != nil {
		self.schedule.Zeroize()
	}
	if self.secretTree != nil {
		self.secretTree.Zeroize()
	}
	self.ownPriv.Zeroize()
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
	// the update path plan is the one piece of key material in the staged commit that no field of
	// this group receives, and it holds the commit secret and every path secret the update path
	// was built from. Its private half is NOT erased here and must not be: it is the leaf state
	// installed six statements above, and (*UpdatePathPlan).Zeroize leaves it alone for that
	// reason.
	staged.plan.Zeroize()
	// AND THE STAGED COMMIT IS RELEASED BEFORE THE REBIND RATHER THAN AFTER IT. Every field of it
	// that holds key material now stands in this group's own storage, so a rebind that refused
	// while self.pending still pointed at it would leave a group whose staged commit and whose
	// live epoch are one epoch -- and the next ClearPendingCommit, which is a caller's ordinary
	// response to a refusal, would erase the epoch this group is running on.
	self.pending = nil
	if err := self.proposals.Rebind(staged.verified); err != nil {
		return err
	}
	return nil
}


// ---------------------------------------------------------------------------
// p7 task 16: joining a group from a Welcome and a ratchet tree the CALLER anchored
// ---------------------------------------------------------------------------

// JoinKeyMaterial is what a joiner holds for the KeyPackage a Welcome names: the key package it
// PUBLISHED, and the three private halves it published nowhere.
//
// The key package is carried by value and the three keys by reference, which is the shape a
// caller already has -- (StateStore).TakeKeyPackage hands back the encoding and the two private
// keys it stored beside it, and the signing key is the device's own. Nothing here is retained by
// the group this material joins: the signing key and the credential are CLONED into it and the
// encryption key is cloned by NewTreeKEMPrivate, so a caller goes on owning every array it passed
// and owes each of them the erase below.
type JoinKeyMaterial struct {
	KeyPackage     KeyPackage
	InitPrivate    HpkePrivateKey
	EncryptPrivate HpkePrivateKey
	SignPrivate    SignaturePrivateKey
}

// Zeroize erases the three private keys this material carries.
//
// It is here because this type DECLARES key material, which is the obligation the erase discipline
// states over the types that hold octets rather than over the call sites somebody remembered: the
// init key opens every Welcome addressed to this key package, the encryption key is this member's
// leaf key for as long as it holds that leaf, and the signing key is its identity. A caller that
// dropped one of these after a join left all three in the heap for the collector to move around.
//
// THE KEY PACKAGE'S PUBLISHED HALF IS DELIBERATELY NOT TOUCHED, for (*WelcomeJoiner).Zeroize's
// reason one file over: every field of its encoding went to the delivery service and to every
// member of every group that added this device, so erasing it would take away nothing an attacker
// lacks while destroying a value the caller still owns.
//
// ITS ONE UNPUBLISHED FIELD IS. signPriv is the seed the leaf's signature key was minted from,
// NewKeyPackage sets it, and marshalCore stops above it -- so a joiner assembled out of a key
// package this process minted is holding a signature private key inside a structure that is
// otherwise entirely public. (*KeyPackage).Zeroize erases that field and leaves the rest, which is
// why the call is to it rather than to a zeroizeSecret written here: this type cannot see whether
// it was handed a minted key package or one decoded off the wire, and the type that can does not
// have to.
//
// A nil receiver is accepted for zeroizeSecret's reason, and the noinline directive is the erase
// class's rule; see (*TreeKEMPrivate).Zeroize.
//
//go:noinline
func (self *JoinKeyMaterial) Zeroize() {
	if self == nil {
		return
	}
	self.KeyPackage.Zeroize()
	zeroizeSecret(self.InitPrivate)
	zeroizeSecret(self.EncryptPrivate)
	zeroizeSecret(self.SignPrivate)
}

// JoinFromWelcome builds this client's group state from a Welcome and a ratchet tree the CALLER
// obtained, following RFC 9420 section 12.4.3.1's receive steps in the order the section states
// them.
//
// WHAT A CALLER MUST ESTABLISH BEFORE IT CALLS THIS, first because nothing below can do it.
//
// A WELCOME AUTHENTICATES NOBODY. It is HPKE-sealed to an init key its recipient PUBLISHED, in a
// key package that went to the delivery service and to every member of every group that added this
// device, so anybody at all holding that key package can build one addressed to it: mint a ratchet
// tree, sign a GroupInfo at a leaf of that tree with a signing key drawn for the purpose, choose a
// joiner secret, seal it to the published init key. Every check this function makes passes on that
// message, and the client that ran them is then a member of a group whose entire membership is one
// attacker. That is not a gap in this function; it is what a Welcome IS. welcome.go's header says
// it from the tree's end, (*GroupInfo).Verify says it under "WHERE THE TREE COMES FROM", and
// BuildWelcome says it over the object it produces.
//
// THE TREE ARRIVING AS A PARAMETER OF ITS OWN DOES NOT CHANGE THAT BY ONE BIT, and the shape is
// named here because it reads as though it does. The attacker supplies both octet strings:
// ratchetTree is exactly as much the sender's as welcome is, and a caller that lifted this
// argument out of the same delivery that carried the Welcome has authenticated nothing that a
// caller reading the tree out of a ratchet_tree extension would not also have "authenticated".
// (*GroupInfo).Verify establishes that a member OF THE TREE IT WAS HANDED signed this GroupInfo
// about THAT tree, and a forged pair agrees with itself perfectly.
//
// So the caller owes an ANCHOR FOR THE TREE THAT DOES NOT COME FROM THE WELCOME. Concretely, before
// it treats the answered group as the group a human meant to join, it must have established --
// over a channel it already authenticates, which in this product means an existing URmessage
// session or something the two people compared out of band -- the tree hash of the epoch it is
// joining, and it must reconcile that value against the tree it passes here. The group id and the
// epoch of the answered group are reachable through (*Group).GroupId and (*Group).Epoch and the
// tree through (*Group).RatchetTree, so the reconciliation has values to run on; this function is
// handed the result of it and cannot audit it.
//
// cfg.GroupId, when the caller sets it, is checked against the group id the Welcome describes.
// THAT IS AN INTENT MATCH AND NOT AUTHENTICATION, and the distinction is the whole reason it is
// spelled out: a group id is public, and an attacker naming the id of the group its target expects
// passes this check on the first try. What it buys is that a caller which said which group it
// meant to join is not silently placed in another one. A caller that does not yet know the id
// leaves the field empty and the check does not run.
//
// WHAT THIS FUNCTION DOES CHECK, once the tree is granted:
//
//  1. the message is a Welcome, and its cleartext ciphersuite is the one this joiner's key package
//     names, the one this profile creates groups under, and the one the provider runs;
//  2. an entry of it is addressed to THIS joiner's key package reference, and that entry opens
//     under THIS joiner's init private key with this Welcome's own encrypted_group_info as the
//     HPKE context -- which is what makes an entry lifted off another Welcome, or a seal made to
//     another joiner's init key, a refusal rather than a group;
//  3. the group secrets name no pre-shared key, which is outside this profile;
//  4. the encrypted group info opens under welcome_key/welcome_nonce derived from the joiner
//     secret that entry carried;
//  5. a member of the tree the caller passed signed that group info about that tree, and the tree
//     hashes to what its group context names -- both through (*GroupInfo).VerifiedContext, which
//     is (*GroupInfo).Verify and nothing else;
//  6. the tree is a valid ratchet tree for that group context: every leaf signature, every parent
//     hash, the required capabilities, the extensions -- (*RatchetTree).ValidateAgainstContext;
//  7. every group context extension is one this profile admits, and the context carries a group
//     policy;
//  8. a leaf of the tree carries this joiner's signature key, and THE LEAF NODE STANDING THERE IS
//     THE ONE THIS JOINER PUBLISHED, byte for byte;
//  9. the confirmation tag the group info carries is the one this joiner's own key schedule
//     produces over the confirmed transcript hash it carries -- which is what says the epoch this
//     joiner derived is the epoch the sender described;
//  10. every path secret it derives from the one the Welcome carried produces the public key the
//     tree already holds at that node -- (*TreeKEMPrivate).Consistent.
//
// WHAT IT DOES NOT CHECK: that the tree is the group's tree, per every paragraph above; that the
// sender is who it claims to be, because a Welcome carries no claim to check; and that the members
// the tree names are people this user knows, which is the product's question and not this
// function's.
//
// THE TREE IS ALWAYS OUT OF BAND HERE. v1 does not put a ratchet_tree extension in the GroupInfo,
// because MASTER section 8.2 already publishes one snapshot record per epoch and a second copy
// inside every Welcome is the same 300 KB again. A GroupInfo that carries one anyway is not
// ignored -- (*GroupInfo).Verify's rule 9 refuses one describing a tree other than the one in hand
// -- and it is still never read as the tree.
func JoinFromWelcome(cfg *GroupConfig, welcome []byte, ratchetTree []byte,
	keys *JoinKeyMaterial) (*Group, error) {

	if cfg == nil {
		return nil, errNilGroupConfig
	}
	crypto := cfg.Crypto
	// refused rather than dereferenced, and refused before any other argument is judged: every
	// seal this function opens, every secret it derives and every signature it checks is taken
	// through the provider, so a caller that passed none passed nothing this function could have
	// used.
	if crypto == nil {
		return nil, fmt.Errorf("%w: every seal this joiner opens and every secret it derives is taken through it",
			ErrNilCryptoProvider)
	}
	if cfg.Store == nil {
		return nil, errNilStateStore
	}
	if keys == nil {
		return nil, errNilJoinKeyMaterial
	}
	// THE JOINER'S OWN TWO HALVES, held together before one octet the SENDER chose is judged.
	//
	// Here rather than beside step 6's leaf comparison, because this is the caller's material and
	// not the message's: every refusal below names something about a Welcome, and a caller whose
	// keyring and whose stored key package have parted company would be sent to look at a message
	// nobody tampered with. Step 6 asks whether the TREE's leaf is the one this joiner published;
	// this asks whether the key this group will sign with is the one that leaf names, which no
	// amount of reading the tree can answer.
	//
	// Through subtle for guardrail 8's class reason, which is the class and not this line: a
	// signature key is public, and every comparison in this package that decides whether a
	// structure is this client's is spelled the one way.
	joinerSignatureKey, err := signaturePublicKeyOf(keys.SignPrivate)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(joinerSignatureKey, keys.KeyPackage.LeafNode.SignatureKey) != 1 {
		return nil, errJoinerSignatureKeyNotTheLeafs
	}
	active := cfg.Profile
	if active == nil {
		active = defaultProfile()
	}

	// step 0: the frame, and the three things the cleartext ciphersuite has to agree with.
	//
	// ParseMLSMessage runs at the DEFAULT vector bound and is not raised here, which is its own
	// comment's decision restated at the one call site that is a stranger's message: this is
	// decoded by a party who is not yet a member, with no group state to check it against and
	// every length in it chosen by whoever sent it.
	message, err := ParseMLSMessage(welcome)
	if err != nil {
		return nil, err
	}
	// THE WIRE FORMAT COMPARISON IS REDUNDANT THROUGH THIS DOOR AND IS KEPT ANYWAY, which is
	// written down because the alternative is a later reader deleting it as noise.
	// (*MLSMessage).UnmarshalMLS refuses a frame carrying any arm its discriminant does not name,
	// so a message ParseMLSMessage accepted cannot have a welcome arm under another wire format --
	// measured, with the comparison deleted the whole of mls and message is green. What it is for
	// is the reading rather than the reachability: this function's contract is "a Welcome", and
	// the arm alone says only that some field of a struct is non nil. A caller inside this package
	// that assembled an MLSMessage rather than decoding one -- which no gate here forbids -- would
	// otherwise reach the joiner's whole derivation with a frame nothing had judged.
	if message.WireFormat != WireFormatWelcome || message.Welcome == nil {
		return nil, fmt.Errorf("%w: it is framed as wire format %#04x",
			errWelcomeWireFormat, uint16(message.WireFormat))
	}
	parsed := message.Welcome
	if parsed.CipherSuite != keys.KeyPackage.CipherSuite {
		return nil, fmt.Errorf("%w: the welcome names %#04x and this joiner's key package names %#04x",
			ErrWelcomeSuiteMismatch, uint16(parsed.CipherSuite), uint16(keys.KeyPackage.CipherSuite))
	}
	if err := active.checkCiphersuiteForCreate(parsed.CipherSuite); err != nil {
		return nil, err
	}
	// and the provider, for NewGroup's reason at the same position: without this the disagreement
	// surfaces two steps later as an AEAD that will not open, which is a refusal naming a group
	// info nobody tampered with.
	if parsed.CipherSuite != crypto.Suite() {
		return nil, fmt.Errorf("%w: the welcome names %#04x and the provider runs %#04x",
			errWelcomeJoinerProviderSuite, uint16(parsed.CipherSuite), uint16(crypto.Suite()))
	}

	// step 1: the entry addressed to the key package this joiner published.
	//
	// Through subtle for guardrail 8's reason, which is the class rather than this line: a key
	// package reference is public, and every comparison in this package that decides whether a
	// structure is ADOPTED is spelled the one way.
	ref, err := keys.KeyPackage.Ref(crypto)
	if err != nil {
		return nil, err
	}
	var entry *EncryptedGroupSecrets
	for i := range parsed.Secrets {
		if subtle.ConstantTimeCompare(parsed.Secrets[i].NewMember, ref) == 1 {
			entry = &parsed.Secrets[i]
			break
		}
	}
	if entry == nil {
		return nil, fmt.Errorf("%w: this welcome carries %d entries and none names %x",
			ErrWelcomeNoMatchingKeyPackage, len(parsed.Secrets), ref)
	}

	// step 2: the group secrets, opened under THIS joiner's init key with THIS Welcome's encrypted
	// group info as the HPKE context.
	//
	// THE HALF OF THE JOINER PAIRING THAT IS NOT A LOOKUP. The step above found the entry that
	// NAMES this key package, which is a field whoever built the Welcome chose; this is the one
	// that cannot be chosen, because the seal was made to the init key that key package published
	// and no other private key opens it. A build where the two disagreed -- BuildWelcome pairing
	// joiner i's reference with joiner j's seal, which is the fork errWelcomeAddPairing exists to
	// refuse on the sending side -- is a refusal here rather than a member that derives an epoch
	// nobody else is in. The context binding is the other half: an entry lifted off a different
	// Welcome no longer opens, because encrypted_group_info is what it was sealed against.
	plaintext, err := OpenWithLabel(crypto, keys.InitPrivate, welcomeHpkeLabel,
		parsed.EncryptedGroupInfo, &entry.EncryptedGroupSecrets)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errWelcomeGroupSecretsDecrypt, err)
	}
	secrets := &GroupSecrets{}
	decodeErr := syntax.Unmarshal(plaintext, secrets)
	// the cleartext GroupSecrets encoding, erased the moment it has been decoded and on the
	// failure path as well -- which is why the erase is written before the error is read. It holds
	// this epoch's joiner secret and this joiner's path secret side by side, and it is a buffer
	// this function produced rather than one a caller owns.
	zeroizeSecret(plaintext)
	if decodeErr != nil {
		return nil, decodeErr
	}
	// and the two secrets the decode lifted out of it, on every path out of this function. Both
	// are COPIED into the values that outlive the call -- NewKeyScheduleFromJoiner clones the
	// joiner secret and DerivePathSecrets clones the rung it starts from -- so what stands here
	// afterwards is a second live copy of the epoch, held by nothing that erases it.
	defer func() {
		zeroizeSecret(secrets.JoinerSecret)
		if secrets.PathSecret != nil {
			zeroizeSecret(secrets.PathSecret.PathSecret)
		}
	}()
	if len(secrets.Psks) != 0 {
		return nil, fmt.Errorf("%w: this welcome names %d pre-shared key(s)",
			errProfilePsk, len(secrets.Psks))
	}

	// step 3: the group info, opened under welcome_key/welcome_nonce with EMPTY AAD.
	//
	// welcome_secret is DeriveSecret(Extract(joiner_secret, psk_secret), "welcome"), and this is
	// the one derivation a joiner has to make outside the key schedule: NewKeyScheduleFromJoiner
	// needs the group context, and the group context is inside the thing this key opens. Extract
	// takes (salt, ikm) through the provider and the joiner secret is the SALT -- guardrail 1, and
	// the transposition compiles and answers a secret exactly as well formed as the right one. The
	// two derivations are held together twelve statements below rather than trusted to agree.
	//
	// The EMPTY AAD is transcribed from RFC 9420 section 12.4.3.1 and is not an omission: an
	// implementation that fed the group context instead seals and opens against itself perfectly
	// and interoperates with nothing.
	memberSecret := crypto.Extract(secrets.JoinerSecret, EmptyPskSecret(crypto))
	welcomeSecret := crypto.DeriveSecret(memberSecret, "welcome")
	zeroizeSecret(memberSecret)
	defer zeroizeSecret(welcomeSecret)
	key, nonce, err := WelcomeKeyNonce(crypto, welcomeSecret)
	if err != nil {
		return nil, err
	}
	infoBytes, err := crypto.AeadOpen(key, nonce, nil, parsed.EncryptedGroupInfo)
	// erased whether or not the open succeeded, for (*RatchetTree).DecryptUpdatePath's reason: the
	// return path that would skip the erase is the one an error takes.
	zeroizeSecret(key)
	zeroizeSecret(nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWelcomeGroupInfoDecrypt, err)
	}
	info := &GroupInfo{}
	if err := syntax.Unmarshal(infoBytes, info); err != nil {
		return nil, err
	}

	// step 4: the tree, and whatever authority the group info has over it.
	//
	// VerifiedContext AND NOT Verify FOLLOWED BY A TREE HASH COMPARISON OF THIS FUNCTION'S OWN.
	// Verify's rule 4 already compares the tree's hash against the group context's tree_hash, and
	// a second comparison here would be a second reading of one question -- the dual
	// representation this package has been rebuilt twice to remove -- which agrees with the first
	// for exactly as long as the two happen to be spelled the same way. The door that answers it
	// is also the door that answers the signature, the version, the suite, the signer bound, the
	// blank signer leaf and the carried ratchet_tree, so a rule added there is added here by
	// existing. What it costs is that this function inherits every gap Verify has, and the biggest
	// of them is the one the header above is entirely about.
	//
	// It answers the VERIFIED context as well, which is what the proposal cache is bound to below:
	// there is exactly one door onto a VerifiedGroupContext and this is a caller of it, rather
	// than a second construction of the same authority.
	tree, err := UnmarshalRatchetTree(ratchetTree)
	if err != nil {
		return nil, err
	}
	verified, err := info.VerifiedContext(crypto, tree)
	if err != nil {
		return nil, err
	}
	// the caller's statement of which group it meant to join, matched and never trusted. See the
	// header: this refuses a joiner being placed in a group it did not ask for, and refuses
	// nothing at all to an attacker who names the id its target expects.
	if len(cfg.GroupId) != 0 &&
		subtle.ConstantTimeCompare(cfg.GroupId, info.GroupContext.GroupId) != 1 {
		return nil, fmt.Errorf("%w: this client asked to join %x and this welcome describes %x",
			errWelcomeGroupIdNotTheOneAsked, cfg.GroupId, info.GroupContext.GroupId)
	}

	// step 5: the tree is a tree of this group at this epoch, and the group is one this profile
	// runs. ValidateAgainstContext is where every leaf signature and every parent hash is checked;
	// without it the group info above has been verified against a leaf of a tree nothing judged.
	requiredCaps, err := requiredCapabilitiesOf(info.GroupContext.Extensions)
	if err != nil {
		return nil, err
	}
	treeCtx := &TreeValidationContext{
		Crypto:          crypto,
		Suite:           info.GroupContext.CipherSuite,
		GroupId:         info.GroupContext.GroupId,
		RequiredCaps:    requiredCaps,
		GroupExtensions: info.GroupContext.Extensions,
		// clamped to one millisecond for (*KeyPackage).Validate's reason: a NowMs of zero is
		// LeafValidationContext's documented opt out of the lifetime check, so a machine whose
		// clock is not set must not turn the one untrustworthy input into the one that disables
		// the check it exists for.
		NowMs:       uint64(max(time.Now().UnixMilli(), 1)),
		ClockSkewMs: leafLifetimeSkewSeconds * 1000,
	}
	if err := tree.ValidateAgainstContext(treeCtx, &info.GroupContext); err != nil {
		return nil, err
	}
	for i := range info.GroupContext.Extensions {
		if err := active.checkGroupExtension(info.GroupContext.Extensions[i].ExtensionType); err != nil {
			return nil, err
		}
	}
	// a group this profile runs carries a policy, and it is asked for here rather than at the
	// first message that needed a role -- which is (*Group).Members, whose answer degrades to
	// RoleMember for every leaf when the policy will not parse.
	if _, err := GroupPolicyOf(info.GroupContext.Extensions); err != nil {
		return nil, err
	}

	// step 6: this joiner's own leaf.
	//
	// FOUND BY SIGNATURE KEY AND THEN HELD TO THE WHOLE LEAF NODE. The lookup alone says only that
	// some leaf carries this device's signature key, and a tree is not known to be free of
	// duplicate signature keys at this point -- FindLeafBySignatureKey's own comment says so, and
	// picks the lowest for that reason. What the joiner actually needs is the leaf the committer
	// installed FROM ITS KEY PACKAGE, because that is the leaf whose encryption key it holds the
	// private half of and the leaf every later signature of its own will be attributed to. A tree
	// carrying this joiner's signature key at a leaf with somebody else's encryption key passes
	// the lookup, passes (*TreeKEMPrivate).Consistent -- which deliberately does not re-derive the
	// leaf public key, there being no private-to-public operation on the provider -- and produces
	// a member that decrypts nothing, with no refusal anywhere to point at.
	ownLeaf, found := tree.FindLeafBySignatureKey(keys.KeyPackage.LeafNode.SignatureKey)
	if !found {
		return nil, fmt.Errorf("%w: no leaf of this tree carries this joiner's signature key",
			ErrWelcomeLeafNotFound)
	}
	if err := leafIsTheOneThisJoinerPublished(tree.Leaf(ownLeaf), &keys.KeyPackage.LeafNode); err != nil {
		return nil, fmt.Errorf("%w: at leaf %d", err, ownLeaf)
	}

	// step 7: the key schedule of the epoch this joiner is entering.
	schedule, err := NewKeyScheduleFromJoiner(crypto, secrets.JoinerSecret,
		EmptyPskSecret(crypto), &info.GroupContext)
	if err != nil {
		return nil, err
	}
	ownPriv := NewTreeKEMPrivate(ownLeaf, keys.EncryptPrivate)
	var secretTree *SecretTree
	// EVERY REFUSAL FROM HERE ON DROPS A FULLY DERIVED EPOCH, and an epoch that is dropped is
	// erased. The schedule holds the init secret, the confirmation key, the encryption secret, the
	// epoch authenticator, the exporter and the resumption PSK; the private state holds this
	// device's leaf key and every path secret laddered above it. After the return nothing in this
	// process can reach any of it, and unreachable is not erased. handedOn is what tells a refusal
	// from the one path that gives all three to a Group that owes them its own Close.
	handedOn := false
	defer func() {
		if handedOn {
			return
		}
		schedule.Zeroize()
		if secretTree != nil {
			secretTree.Zeroize()
		}
		ownPriv.Zeroize()
	}()

	// the welcome secret this function derived in step 3 and the one the schedule derives from the
	// same joiner secret are the SAME value by definition, and they are compared rather than
	// assumed to be. They are two transcriptions of DeriveSecret(Extract(joiner_secret,
	// psk_secret), "welcome") in two files, which is the shape guardrail 1 is about: a transposed
	// Extract in either of them answers KDF.Nh well formed octets, and every test that does not
	// hold the two against each other passes. This is a build disagreeing with itself rather than
	// anything a peer did -- the same kind of refusal errCreationConfirmationTag makes in NewGroup
	// -- and the alternative to making it is a joiner that opened the group info with one epoch's
	// key and runs on another.
	if subtle.ConstantTimeCompare(welcomeSecret, schedule.WelcomeSecret()) != 1 {
		return nil, errJoinerWelcomeSecret
	}
	// ValSem205 from the joining side: the tag the group info carries is the one THIS joiner's
	// confirmation key produces over the confirmed transcript hash THIS group info names. It is
	// what turns "the sender described an epoch" into "the epoch I derived is that epoch", and it
	// is the only check here that reaches the joiner secret at all. Through
	// (*KeySchedule).VerifyConfirmationTag and therefore through CryptoProvider.MacVerify and
	// crypto/subtle -- guardrail 8 -- which is also what refuses a truncated tag rather than
	// comparing as much of it as fits.
	if !schedule.VerifyConfirmationTag(info.GroupContext.ConfirmedTranscriptHash, info.ConfirmationTag) {
		return nil, fmt.Errorf("%w: this welcome describes an epoch this joiner does not derive",
			errBadConfirmationTag)
	}
	transcript := InitialTranscriptHashes()
	if err := transcript.SetFromGroupInfo(crypto,
		info.GroupContext.ConfirmedTranscriptHash, info.ConfirmationTag); err != nil {
		return nil, err
	}

	// step 8: the private tree state -- this device's leaf key, and the ladder above the node it
	// shares with the sender.
	//
	// Consistent re-derives each held secret's node key pair and requires the derived public key to
	// be the one the tree already carries at that node, RFC 9420 section 12.4.3.1: "The private key
	// MUST be the private key that corresponds to the public key in the node." It runs whether or
	// not a path secret arrived, because a state holding nothing but a leaf index still asserts
	// that the tree has a leaf there.
	if secrets.PathSecret != nil {
		if err := tree.installJoinerPathSecrets(crypto, ownPriv, ownLeaf, info.Signer,
			secrets.PathSecret.PathSecret); err != nil {
			return nil, err
		}
	}
	if err := ownPriv.Consistent(crypto, tree); err != nil {
		return nil, err
	}

	secretTree, err = NewSecretTree(crypto, tree.LeafWidth(), schedule.Secrets().Encryption)
	if err != nil {
		return nil, err
	}
	proposals, err := NewProposalCache(verified)
	if err != nil {
		return nil, err
	}

	group := &Group{
		// THE STORE AND NOT THE CONFIG, which is Group's own field comment: a config is a caller's
		// structure and the caller goes on holding it, and every other field this join needs comes
		// out of the group info rather than out of the config. The group id, the extensions and
		// the suite this group runs are the EPOCH's, and a join that installed the caller's copies
		// of them would be a member whose published context and whose epoch secrets can part
		// company.
		store:  cfg.Store,
		crypto: crypto,
		// both COPIED, for NewGroup's reason: they are arrays the caller owns and goes on using,
		// and this group signs with the one and names itself with the other for the whole of its
		// life.
		signer: SignaturePrivateKey(cloneBytes(keys.SignPrivate)),
		cred: Credential{
			CredentialType: keys.KeyPackage.LeafNode.Credential.CredentialType,
			Identity:       cloneBytes(keys.KeyPackage.LeafNode.Credential.Identity),
		},
		ownLeaf:     ownLeaf,
		ownPriv:     ownPriv,
		tree:        tree,
		context:     &info.GroupContext,
		verified:    verified,
		schedule:    schedule,
		secretTree:  secretTree,
		transcript:  transcript,
		proposals:   proposals,
		restoreKind: restoreFromJoiner,
	}
	if err := group.persist(); err != nil {
		return nil, err
	}
	handedOn = true
	return group, nil
}

// leafIsTheOneThisJoinerPublished compares the leaf standing in the tree against the leaf this
// joiner's key package published, as ENCODINGS.
//
// The encoding and not a field by field comparison, for the reason (*GroupInfo).Verify compares
// tree hashes rather than tree encodings, read the other way round: what is being asked is whether
// these are the same leaf node, and a comparison written over the fields somebody listed answers
// that question about the fields somebody listed. A leaf that grew a tenth field would be compared
// over nine of them, silently, and the encoding is the one reading that cannot fall behind the
// struct. Through subtle for the class reason guardrail 8 states.
func leafIsTheOneThisJoinerPublished(inTree *LeafNode, published *LeafNode) error {
	// a blank leaf is refused as an absent leaf and not as a mismatched one: FindLeafBySignatureKey
	// skips blanks, so this arm is reachable only from a tree that changed under us, and a caller
	// told "your leaf is not the one you published" would go looking at its key package.
	if inTree == nil {
		return fmt.Errorf("%w: the tree holds no leaf where this joiner's signature key was found",
			ErrWelcomeLeafNotFound)
	}
	here, err := syntax.Marshal(inTree)
	if err != nil {
		return err
	}
	mine, err := syntax.Marshal(published)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(here, mine) != 1 {
		return errWelcomeLeafNotTheJoiners
	}
	return nil
}

// installJoinerPathSecrets seeds the joiner's ladder from the one rung its Welcome carried.
//
// The Welcome carries the secret for the LOWEST NODE THE JOINER'S LEAF AND THE SENDER'S LEAF SHARE
// and for no other node, RFC 9420 section 12.4.3.1 -- it is also exactly the node the joiner is not
// sealed to in the UpdatePath itself, because a member added by the same commit holds no key yet.
// Every node above it is one DeriveSecret(., "path") away, which is what DerivePathSecrets returns
// as a chain.
//
// THE WALK IS OVER THE SENDER'S FILTERED DIRECT PATH AND NOT OVER THE JOINER'S UNFILTERED ONE, and
// the two are different node lists. The ladder the sender built runs over its own FILTERED path --
// CreateUpdatePathSecrets derives one rung per node of it, and (*RatchetTree).DecryptUpdatePath
// walks that same list from the shared node upward on the receiving side -- so a joiner laddering
// over its unfiltered direct path would place the sender's rung k at the tree's node k+j for
// whatever j the filter dropped, and every node from the first dropped one upward would hold a
// secret that derives a key pair nothing in the tree matches. (*TreeKEMPrivate).Consistent refuses
// that, so the symptom is a joiner that cannot join rather than one that joins wrongly; the reason
// it is written here is that the two paths COINCIDE in the shapes a small fixture produces, and a
// round trip through a two or three member group cannot tell them apart.
//
// Above the shared node the sender's filtered path and the joiner's are the same list, which is why
// walking the sender's is walking the joiner's: for a node above the common ancestor both leaves
// sit in the same child subtree, so the copath child the filter tests is the same node for both.
//
// The refusal for a shared node that is not on the sender's path is not the ordinary case -- it is
// (*RatchetTree).DecryptUpdatePath's ErrNoPathSecret condition read from the other end -- but here
// it means a Welcome that handed this joiner a path secret for an epoch whose update path never
// covered it, which is a message to refuse rather than a state to build.
// A METHOD ON THE TREE, where (*RatchetTree).EncryptUpdatePath, MergeUpdatePath and
// DecryptUpdatePath are: every fact it reads is the tree's -- the sender's filtered direct path and
// the node the two leaves share -- and the private state it writes into is a caller's, exactly as
// it is for the decrypt half.
func (self *RatchetTree) installJoinerPathSecrets(crypto CryptoProvider, priv *TreeKEMPrivate,
	own LeafIndex, signer LeafIndex, pathSecret []byte) error {

	// the provider first, before the tree is read: every rung of the ladder below is a
	// DeriveSecret through it and the width check reads KDF.Nh off it, so a caller that passed
	// none passed nothing this method could have used. Bare rather than wrapped, which is
	// DeriveNodeKeyPair's spelling for the same condition.
	if crypto == nil {
		return ErrNilCryptoProvider
	}
	steps, err := self.filteredPathSteps(signer)
	if err != nil {
		return err
	}
	lowest := CommonAncestor(signer.NodeIndex(), own.NodeIndex())
	start, onThePath := indexOfStep(steps, lowest)
	if !onThePath {
		return fmt.Errorf("%w: node %d is the lowest node leaf %d and leaf %d share, and it is not on leaf %d's filtered direct path",
			errWelcomePathSecretNode, lowest, own, signer, signer)
	}
	// the width, checked before the ladder for (*RatchetTree).DecryptUpdatePath's reason at the
	// same position: everything below this line agrees with a sender that agrees with itself, so
	// this is the last place a wrong width is a statement about a message rather than about an
	// epoch. It is a length and carries no secret, so the comparison is a plain one.
	if len(pathSecret) != crypto.HashSize() {
		return fmt.Errorf("%w: this welcome carries a path secret of %d octets, want %d",
			errPathSecretLength, len(pathSecret), crypto.HashSize())
	}
	// one secret per node from the shared node to the root, which is len(steps)-start of them.
	// DerivePathSecrets answers count+1 rungs -- the extra one is the rung past the root that
	// section 8.1 makes the commit secret, which a joiner has no use for -- so the count is one
	// less than the number of nodes. Asking for len(steps)-start here indexes one past the end of
	// the path.
	chain := DerivePathSecrets(crypto, pathSecret, len(steps)-start-1)
	for i, secret := range chain {
		priv.PathSecrets[steps[start+i].Node] = secret
	}
	return nil
}

// ---------------------------------------------------------------------------
// p7 task 18: RFC 9420 section 12.4.2, the receive half of a commit
// ---------------------------------------------------------------------------

// The refusals ingesting a message makes that are nobody else's, one value per rule for the reason
// this file's first error block states.
var (
	// errProcessWireFormat is an MLSMessage this profile does not process on a group's inbound
	// path. It is a PROFILE refusal and not a codec one: the codec accepts all five wire formats
	// -- a Welcome and a KeyPackage are perfectly well formed messages -- and what refuses them
	// here is that neither is something a group at an epoch ingests. Spec A section 3.4 sends
	// every handshake message as a PrivateMessage, so PublicMessage is refused too and the
	// receive path has one shape rather than two.
	errProcessWireFormat = errors.New("mls: this profile does not process that wire format on a group's inbound path")

	// errProcessSenderType is a framed content from a sender type this build has no key for. It
	// is NOT errProfileExternalSender, which is the external_senders GROUP CONTEXT EXTENSION
	// refused at a proposal door: that one is a group whose extensions this profile will not
	// carry, and this one is a message whose signer this member cannot name. A caller sent to
	// look at its group's extensions over a message from an external sender would find nothing
	// wrong with them.
	errProcessSenderType = errors.New("mls: the v1 profile processes member senders only")

	// errProcessContentType is a framed content whose content_type is outside RFC 9420 section
	// 6's three. The codec refuses an undefined code point, so what could reach this is a type
	// this select has not been taught, and answering it is what keeps a fourth arm from being a
	// silent fall through to nil.
	errProcessContentType = errors.New("mls: framed content of a type this receive path does not process")

	// errCommitContentCarriesNoCommit is a content_type of commit with no commit inside it. The
	// codec pairs the two, so this is this build disagreeing with itself rather than anything a
	// peer did -- and it is stated rather than dereferenced because the alternative is a nil
	// dereference inside the receive path of a library.
	errCommitContentCarriesNoCommit = errors.New("mls: a commit message carries no commit")

	// errApplyCommitNotACommit is ApplyCommit handed something ProcessMessage did not answer as a
	// commit. It is a caller's mistake and not a message fault, which is why it is not one of the
	// three above.
	errApplyCommitNotACommit = errors.New("mls: ApplyCommit was handed a result that is not a staged commit")

	// errUpdatedLeafPrivateKey is a commit that installs an Update at THIS client's own leaf whose
	// encryption key this client cannot produce the private half of.
	//
	// It is the receiving end of the order (*Group).ProposeUpdate files its key pair in: the
	// private half goes into the store BEFORE the proposal is published, precisely so that a
	// committer acting entirely correctly on what it was sent cannot commit this client into an
	// epoch whose own leaf key it does not hold. This is the value for the case where the store
	// nonetheless has no answer -- a store that lost the entry, or a leaf updated by somebody
	// else, which ValSem111 forbids and this refuses rather than assumes.
	//
	// A REFUSAL AND NOT A CARRY-FORWARD, which is the whole reason it exists. The alternative is
	// keeping the leaf key of the epoch that just closed, and that produces a member which merges
	// the commit, enters the new epoch, and then decrypts NOTHING for the rest of the group's life
	// -- every update path sealed to its published key, opened with a key that is not its private
	// half, reported at the far end as a corrupt commit.
	errUpdatedLeafPrivateKey = errors.New(
		"mls: this commit updates this client's own leaf and its private half is not in the store")
)

// checkWireFormat is the v1 disposition of the wire formats a GROUP INGESTS, standing in for
// (*Profile).CheckWireFormat exactly as checkCiphersuiteForCreate stands in for
// (*Profile).CheckCiphersuiteForCreate; see proposal_list.go's profile for why the stand-in is
// unexported and what the swap costs.
//
// PrivateMessage AND NOTHING ELSE, and the refusals are two different sentences. A Welcome, a
// GroupInfo and a KeyPackage are messages a group at an epoch does not ingest at all --
// JoinFromWelcome takes the first two and the directory takes the third -- and a PublicMessage is
// a handshake message this profile does not send, because spec A section 3.4 has handshake traffic
// travel as a PrivateMessage so that the delivery service learns neither who committed nor what
// the commit did. A build that accepted one would let a peer choose which of the two
// authenticators its message is judged under.
//
// THERE IS NO checkVersion BESIDE IT, and that is a decision rather than the omission it looks
// like. (*MLSMessage).UnmarshalMLS refuses every ProtocolVersion but mls10 INLINE, before it
// selects an arm, so a second version gate here could not be reached by any octets this package
// can parse -- and a guard no input can fire is the shape (*Group).RatchetTree and
// (*Group).ProposeGroupContextExtensions both reject: a second copy covering for the one really
// doing the work, which no test can tell apart from the real answer. When p8's Profile makes the
// version a profile decision, the door it needs is the decoder's rather than one written here.
func (self *profile) checkWireFormat(format WireFormat) error {
	if format == WireFormatPrivateMessage {
		return nil
	}
	return fmt.Errorf("%w: wire format %d", errProcessWireFormat, format)
}

// ProcessedKind discriminates what ProcessMessage returned.
type ProcessedKind uint8

const (
	ProcessedApplication ProcessedKind = 1
	ProcessedProposal    ProcessedKind = 2
	ProcessedCommit      ProcessedKind = 3
)

// ApplicationMessage is one decrypted application message, as storage the caller owns: every field
// of it was cut out of a plaintext this call decrypted, and nothing in this package retains it.
type ApplicationMessage struct {
	SenderLeaf        LeafIndex
	AuthenticatedData []byte
	Plaintext         []byte
}

// Processed is the result of ingesting one MLSMessage.
//
// Exactly one of the three arms is populated and Kind says which, which is MLSMessage's own select
// discipline one layer up: a caller reading the wrong arm of a value with two populated would be
// acting on a message nobody sent.
type Processed struct {
	Kind        ProcessedKind
	Sender      Sender
	Application *ApplicationMessage
	Proposal    *Proposal
	Commit      *StagedCommit
}

// ProcessMessage ingests one MLSMessage.
//
// IT NEVER MUTATES LIVE EPOCH STATE. A commit comes back STAGED, so the caller can run its own
// policy and record the epoch's wraps before the epoch advances -- connect/message needs that gap,
// and a receive path that advanced the epoch as it validated would leave a caller that refused the
// commit already inside it. (*Group).ApplyCommit is the second half.
//
// TWO THINGS DO MOVE, and both are meant to, exactly as they are on the proposal generation path
// one section up. An inbound PROPOSAL is cached, because that is what makes a later commit able to
// name it by reference; and the message ratchet of the SENDER's leaf advances a generation, which
// is what opening a PrivateMessage is.
//
// The order is RFC 9420 section 6's and it is not interchangeable: the message is parsed, the
// profile judges the envelope, the framing layer opens and authenticates it, and only then is the
// content read. A body that branched on the content type before the open would be branching on an
// attacker's octets.
func (self *Group) ProcessMessage(message []byte) (*Processed, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, errGroupClosed
	}

	parsed, err := ParseMLSMessage(message)
	if err != nil {
		return nil, err
	}
	if err := defaultProfile().checkWireFormat(parsed.WireFormat); err != nil {
		return nil, err
	}
	// THERE IS NO ARM CHECK BESIDE IT, and its absence is a decision rather than the omission it
	// looks like -- the same one stageInboundCommitLocked makes about the confirmation tag.
	// (*MLSMessage).UnmarshalMLS populates the arm its wire format names and refuses a message
	// carrying any other, so behind the gate above parsed.PrivateMessage is non-nil for every
	// message this package can parse. A guard here would answer the SAME sentinel that gate does,
	// which is worse than redundant: no input could tell the two apart, so a profile that had
	// stopped refusing a Welcome would go on reading as one that refuses it. MEASURED, on the
	// mutation that says so -- with checkWireFormat accepting every format, the arm check kept the
	// whole suite green and TestProcessMessageRefusesEveryWireFormatButPrivateMessage passed on the
	// wrong refusal.
	//
	// The direction is unchanged: OpenPrivateMessage refuses a nil message with errNilPrivateMessage
	// before it reads anything off it, so a build that somehow reached this line without one fails
	// closed rather than dereferencing.

	groupContext, err := syntax.Marshal(self.context)
	if err != nil {
		return nil, err
	}

	authenticated, err := OpenPrivateMessage(self.crypto, self.secretTree,
		self.senderDataSecretLocked(), parsed.PrivateMessage,
		self.signatureKeyResolverLocked(), groupContext)
	if err != nil {
		return nil, err
	}
	return self.processAuthenticatedLocked(authenticated)
}

// signatureKeyResolverLocked is what turns a Sender into the key the framing layer verifies
// against, and it is where ValSem004 and this profile's sender rule are enforced: an external
// sender or a blank leaf never yields a key, so a message from either is refused at the signature
// rather than further in, where its leaf index would already have been used for something.
//
// A DECLARATION AND NOT A CLOSURE INSIDE ProcessMessage, and the difference is what a test can
// reach. OpenPrivateMessage constructs the Sender it resolves -- section 6.3's sender data carries
// a leaf index and nothing else, so every sender that reaches this through the one wire format this
// profile ingests is a member sender. The non-member arm is therefore a refusal no octets can fire,
// and written as a lambda it would be a refusal nothing in this package has ever read, which is
// exactly what validation_framing_test.go's two refusal gates exist to report. It is kept rather
// than deleted because it is the fail-CLOSED half: CheckSenderLeaf answers nil for every non-member
// sender by design, so a body without this arm would fall through to leaf 0's key for a sender type
// that carries no leaf index at all.
func (self *Group) signatureKeyResolverLocked() SignatureKeyResolver {
	return func(sender Sender) (SignaturePublicKey, error) {
		if sender.SenderType != SenderTypeMember {
			return nil, fmt.Errorf("%w: sender type %d", errProcessSenderType, sender.SenderType)
		}
		// ValSem004, through the framing plan's own door rather than through a second occupancy
		// test written here, so the sender side and the receiver side cannot come to disagree
		// about what an occupied leaf is.
		if err := CheckSenderLeaf(sender, func(leaf LeafIndex) bool {
			return self.tree.Leaf(leaf) != nil
		}); err != nil {
			return nil, err
		}
		leaf := self.tree.Leaf(sender.LeafIndex)
		if leaf == nil {
			return nil, fmt.Errorf("%w: leaf %d", errBlankSenderLeaf, sender.LeafIndex)
		}
		// a COPY of the key and not the tree's own array. SignaturePublicKey is a []byte, so what
		// this hands the framing layer would otherwise be a window onto the live ratchet tree --
		// the same hazard (*Group).Members answers a clone for, and it costs 32 octets a message.
		return SignaturePublicKey(cloneBytes(leaf.SignatureKey)), nil
	}
}

// processAuthenticatedLocked is the content half of ProcessMessage: RFC 9420 section 6's context
// rules over a framed content that has been opened and authenticated, and the select over its three
// content types.
//
// A DECLARATION AND NOT A BLOCK, for signatureKeyResolverLocked's reason one door up. The codec
// refuses every content_type outside the registry, so the arm that answers an undefined one cannot
// be reached through ProcessMessage by any octets at all -- and a refusal nothing has ever read is
// the shape framing_test.go's code point gate reports. Written as a declaration it is reachable
// with a content this package's own encoder cannot produce, which is what makes the message a
// caller would see something a test has actually looked at.
//
// The compiler directive is this package's convention for a member of the class
// TestEveryEraseHelperCarriesTheNoInlineDirective derives, and not a claim that this body erases a
// secret itself. That class is closed under the hand-off -- a declaration that gives storage it was
// handed to an eraser is a member -- and this one hands its argument to (*ProposalCache).Store and
// to stageInboundCommitLocked, both of which are in it. (*ProposalCache).Store carries the
// directive under exactly this reading and says so, which is the point of deriving a class rather
// than listing one.
//
//go:noinline
func (self *Group) processAuthenticatedLocked(authenticated *AuthenticatedContent) (*Processed, error) {
	// ValSem002 and ValSem003, through the framing plan's one check so that the sender side and
	// the receiver side cannot disagree about what "this group, this epoch" means. It runs AFTER
	// the open because a PrivateMessage has no framed content until it has been decrypted.
	if err := CheckFramedContentContext(&authenticated.Content,
		self.context.GroupId, self.context.Epoch); err != nil {
		return nil, err
	}
	sender := authenticated.Content.Sender

	switch authenticated.Content.ContentType {
	case ContentTypeApplication:
		return &Processed{
			Kind:   ProcessedApplication,
			Sender: sender,
			Application: &ApplicationMessage{
				SenderLeaf:        sender.LeafIndex,
				AuthenticatedData: authenticated.Content.AuthenticatedData,
				Plaintext:         authenticated.Content.ApplicationData,
			},
		}, nil
	case ContentTypeProposal:
		// stored through the cache rather than kept here, because the cache is what re-runs the
		// profile gate, checks the epoch binding and applies section 12.2's per sender and per
		// leaf ceilings. The entry it keeps is a CLONE of the proposal, so what is answered below
		// shares no storage with what a later commit resolves.
		if _, err := self.proposals.Store(self.crypto, self.context, authenticated); err != nil {
			return nil, err
		}
		return &Processed{Kind: ProcessedProposal, Sender: sender,
			Proposal: authenticated.Content.Proposal}, nil
	case ContentTypeCommit:
		staged, err := self.stageInboundCommitLocked(authenticated)
		if err != nil {
			return nil, err
		}
		return &Processed{Kind: ProcessedCommit, Sender: sender, Commit: staged}, nil
	}
	return nil, fmt.Errorf("%w: content type %d", errProcessContentType, authenticated.Content.ContentType)
}

// stageInboundCommitLocked is the receive half of RFC 9420 section 12.4.2, in the order the RFC
// lists the steps, with the state lock already held.
//
// THE ORDER IS NORMATIVE AND EVERY STEP DEPENDS ON THE ONE BEFORE IT, which is why it is numbered
// in the body against the RFC's own list rather than left to be read off the lines:
//
//   - the proposals are resolved and applied BEFORE the commit is judged, because every rule of
//     section 12.4 is stated over the tree the proposals build;
//   - the commit is judged BEFORE the update path is merged, because ValSem206 and ValSem207 ask
//     that no key the path publishes already stands in that tree -- and after the merge every one
//     of them does. CheckUpdatePathKeyUniqueness says so in as many words, and a validator handed
//     the merged tree refuses every honest commit of a group with more than one member;
//   - the path is merged BEFORE it is decrypted, because the ciphertexts were sealed under a group
//     context whose tree_hash covers the path's own public keys;
//   - the key schedule is advanced BEFORE the confirmation tag is checked, because the
//     confirmation key belongs to the epoch this commit OPENS;
//   - and the tag is checked against the NEW confirmed transcript hash. A tag checked against the
//     transcript of the epoch that is closing still produces KDF.Nh octets and still compares equal
//     on both sides of an honest exchange, so nothing that round trips can land on that fault.
//
// NOTHING HERE WRITES A FIELD OF THE GROUP. ApplyProposals clones the tree, DecryptUpdatePath is
// handed a Clone of this member's private tree state, and the transcript is a Clone -- so a commit
// refused at any of the returns below leaves this group exactly where the epoch it is still in put
// it.
func (self *Group) stageInboundCommitLocked(authenticated *AuthenticatedContent) (*StagedCommit, error) {
	commit := authenticated.Content.Commit
	if commit == nil {
		return nil, errCommitContentCarriesNoCommit
	}
	committer := authenticated.Content.Sender.LeafIndex
	// THERE IS NO PRESENCE CHECK ON THE CONFIRMATION TAG HERE, and its absence is a decision rather
	// than the omission it looks like. ValSem009 is already stated twice on the way in and once more
	// on the way through: (*FramedContentAuthData).UnmarshalMLS refuses an empty tag as it decodes,
	// VerifyAuthenticatedContent refuses a commit carrying none immediately after the signature, and
	// ValSem205ConfirmationTag refuses one at step 7 under the same sentinel. A fourth copy could not
	// be reached by any octets this package can parse, which is the shape (*Group).RatchetTree and
	// (*Group).ProposeGroupContextExtensions both reject -- a guard covering for the one really doing
	// the work, that no input can tell apart from the real answer. The direction is unchanged: a
	// commit that somehow reached this body with no tag is refused at step 7 rather than accepted.

	// step 1: resolve the proposals this commit names, against THIS member's cache and THIS
	// member's epoch. Erratum 8815 -- "a reference to a proposal that was not previously received"
	// -- is the same rule and the same value, asked here by Resolve rather than restated;
	// ValidateCommit reaches it again through validateCommitErrata, over the cache this step read.
	list, err := self.proposals.Resolve(self.crypto, self.context, committer, commit.Proposals)
	if err != nil {
		return nil, err
	}

	// step 2: apply the list to a tree of this call's own, and judge it against the PRE-commit
	// state, which is the state section 12.2's rules are stated over.
	applied, err := ApplyProposals(self.tree, self.context, self.ownLeaf, list)
	if err != nil {
		return nil, err
	}
	if err := ValidateProposalList(&ProposalValidationInput{
		Crypto:     self.crypto,
		Tree:       self.tree,
		Context:    self.context,
		Extensions: applied.Extensions,
		Committer:  committer,
		List:       list,
		Now:        time.Now(),
	}); err != nil {
		return nil, err
	}

	// step 3: the commit that ejects this client, answered before anything is derived.
	//
	// A REMOVED MEMBER CANNOT DERIVE THE EPOCH AND MUST NOT PRETEND TO, and that is a fact about
	// the protocol rather than a shortcut taken here. Its leaf is blank in the tree the proposals
	// built, so the committer's filtered direct path no longer covers it, no ciphertext of the
	// update path is addressed to it, and there is therefore no commit secret -- which means no
	// key schedule, no confirmation key, and no way to check the confirmation tag. Every remaining
	// rule of section 12.4.2 is a question about an epoch this client does not enter, and
	// ValSem203 answers exactly that: this leaf shares no node with the committer's filtered path.
	//
	// So what is handed back is a REPORT and not an epoch: the committer, the proposals, the
	// leaves that moved, and RemovesSelf. (*Group).ApplyCommit answers ErrRemovedFromGroup for it
	// and closes the group rather than merging anything, and the staged value holds no key
	// material for that close to erase.
	//
	// The commit is not unauthenticated at this point: it opened under this epoch's message keys,
	// its signature verified against the committer's own leaf, and it names this group and this
	// epoch. What is missing is the confirmation tag, and no build can supply that to a member the
	// commit removed.
	if applied.SelfRemoved {
		return &StagedCommit{
			committer:   committer,
			epoch:       self.context.Epoch + 1,
			tree:        applied.Tree,
			list:        list,
			commit:      commit,
			added:       applied.AddedLeaves,
			removed:     applied.RemovedLeaves,
			updated:     applied.UpdatedLeaves,
			selfRemoved: true,
			hasPath:     commit.Path != nil,
			confirmTag:  authenticated.Auth.ConfirmationTag,
		}, nil
	}

	// step 4: section 12.4's own rules, over the post-proposal tree and BEFORE the merge.
	//
	// PostTree IS THE TREE THE PROPOSALS BUILT AND NOT THE ONE THE PATH IS MERGED INTO, which is
	// (*Group).CreateCommit's split at the other end of the same file and is here for the reason
	// CheckUpdatePathKeyUniqueness states: the keys an update path publishes are the keys the merge
	// installs, so a validator handed the merged tree finds every one of them already standing
	// there and refuses ValSem207 on every commit that carries a path.
	//
	// The context is the PRE-commit one and the extensions are the post-proposal set, which is not
	// a muddle and is CreateCommit's pairing for its stated reason: the by-reference arm of the
	// vector join resolves against this member's cache, which is bound to the epoch that is
	// closing, and effectiveExtensions is the field that carries the post-proposal set to the
	// rules that need it.
	commitInput := &CommitValidationInput{
		Crypto:     self.crypto,
		PreTree:    self.tree,
		PostTree:   applied.Tree,
		Context:    self.context,
		Extensions: applied.Extensions,
		Committer:  committer,
		Own:        self.ownLeaf,
		List:       list,
		Commit:     commit,
		Pending:    self.proposals,
		Now:        time.Now(),
	}
	if err := ValidateCommit(commitInput); err != nil {
		return nil, err
	}

	// step 5: this client's own leaf key, if the commit's proposals replaced it.
	//
	// AN UPDATE AT THIS CLIENT'S OWN LEAF IS AN UPDATE THIS CLIENT PUBLISHED -- ValSem111 makes an
	// Update's sender the leaf it updates -- so the private half is one this client drew and filed
	// in its own store before it published the proposal. It has to be installed BEFORE the path is
	// decrypted, because the committer sealed this member's rung of the update path to the key the
	// UPDATE published and not to the one the epoch that is closing carries.
	//
	// MEASURED, which is why it is a step of its own rather than a line inside the path block:
	// without it, a member whose Update another member commits is refused at DecryptUpdatePath on
	// the very commit that carried its own proposal -- and on every commit after that one, because
	// the leaf key it goes on holding is one the group replaced.
	commitSecret := ZeroSecret(self.crypto)
	ownPriv := self.ownPriv
	replaced, err := self.updatedOwnLeafPrivateLocked(applied)
	if err != nil {
		return nil, err
	}
	if replaced != nil {
		// erased when this call returns, whatever it returns: every path below takes a CLONE of
		// this state or replaces it with the one the decrypt answered, so it is never the value
		// handed on and after the return nothing in this process can reach it.
		defer replaced.Zeroize()
		ownPriv = replaced
	}

	// step 6: the path, in the ordered steps section 12.4.2 gives it.
	if commit.Path != nil {
		// RFC 9420 section 7.3's COMMIT door -- the third of the leaf validator's three
		// expectations, and the one that decides the leaf of a RECEIVED update path is signed, is
		// sourced commit, and carries a credential and capabilities this group admits.
		//
		// IT RUNS BEFORE THE MERGE, which is the whole of why it stands here rather than after it.
		// MergeUpdatePath compares a recomputed parent hash chain against path.LeafNode.ParentHash
		// and says in as many words that it does not verify the leaf's signature -- and parent_hash
		// is a field only the commit arm of section 7.6's select signs over. A merge run first
		// would be comparing its chain against an unsigned field, on a tree it has already begun to
		// adopt.
		//
		// The context it is judged in carries the POST-PROPOSAL extension set, so that a commit
		// which changes the group's extensions and publishes a path in one step is judged against
		// the extensions it installs. That is erratum 8745's own pairing, and effectiveContext is
		// where this package states it once.
		if err := ValidateUpdatePathLeafNode(self.crypto, commitInput.effectiveContext(),
			committer, commit.Path); err != nil {
			return nil, err
		}
		if err := applied.Tree.MergeUpdatePath(self.crypto, committer, commit.Path); err != nil {
			return nil, err
		}
		pathTreeHash, err := applied.Tree.TreeHash(self.crypto)
		if err != nil {
			return nil, err
		}
		// the provisional context carries the PREVIOUS epoch's confirmed transcript hash, because
		// the new one is a function of this very commit. Section 12.4.1 has the sender seal the
		// path under exactly this context, so what matters is that the two sides build the same
		// one; (*Group).CreateCommit builds it from the same six fields.
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
		// a CLONE of this member's private tree state, because a decrypt that wrote the new rungs
		// through the live one would have replaced the epoch this group is still running on before
		// anything below got the chance to refuse the commit. PathDecryptResult's own header
		// states the contract from the other side.
		//
		// The leaves this commit ADDS are excluded, which is the receiving half of the exclusion
		// (*Group).CreateCommit makes: a member added by this commit receives the path secret in
		// its Welcome and is sealed to nowhere in the update path.
		decrypted, err := applied.Tree.DecryptUpdatePath(self.crypto, committer, commit.Path,
			provisionalBytes, ownPriv.Clone(), applied.AddedLeaves)
		if err != nil {
			// the cryptographic half of ValSem203; the structural half ran in ValidateCommit, and
			// both carry the same sentinel so a caller can ask the question with one errors.Is
			return nil, fmt.Errorf("%w: %w", errPathDecrypt, err)
		}
		commitSecret = decrypted.CommitSecret
		ownPriv = decrypted.Private
	} else if ownPriv != nil {
		// a commit with no path leaves this client's own leaf key where it was, so the private
		// state carries forward -- and it is CLONED for (*Group).CreateCommit's stated reason: a
		// staged commit is erased when it is dropped, so a staged commit holding this group's own
		// live leaf state would erase, on that ordinary path, the key the epoch this group is
		// still in opens its update paths with.
		ownPriv = ownPriv.Clone()
	}

	// step 7: the new transcript hashes, the new group context and the new key schedule.
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

	// EVERY REFUSAL FROM HERE DOWN DROPS A WHOLE DERIVED EPOCH, and a derived epoch that becomes
	// unreachable is not a derived epoch that was erased. The schedule holds the init secret, the
	// confirmation key, the encryption secret, the epoch authenticator, the exporter and the
	// resumption PSK, and ownPriv is either the leaf state this path decrypted or a clone of this
	// group's own -- so the erase is written once, here, rather than at each of the five returns
	// below, and the flag is what keeps it off the one path where the StagedCommit takes ownership.
	// It is (*Group).CreateCommit's `handedOn` at the other end of the same file.
	handedOn := false
	defer func() {
		if handedOn {
			return
		}
		schedule.Zeroize()
		ownPriv.Zeroize()
	}()

	// step 8: ValSem205, the group's fork detector, against the confirmed transcript hash of the
	// epoch this commit OPENS and under the confirmation key of that same epoch.
	//
	// Both halves are load bearing. The tag is a MAC over the NEW confirmed transcript hash, so a
	// build that checked it before the transcript advanced would be comparing a value both sides
	// agree on whatever the commit did; and the key is the NEW epoch's, which is why this rule is
	// not one of ValidateCommit's twelve and is run by the caller that has a schedule. The
	// comparison goes through CryptoProvider.MacVerify, the only route to a tag comparison this
	// package allows.
	commitInput.ConfirmationKey = schedule.Secrets().Confirmation
	commitInput.ConfirmedHash = confirmedHash
	commitInput.ConfirmationTag = authenticated.Auth.ConfirmationTag
	if err := ValSem205ConfirmationTag(commitInput); err != nil {
		return nil, err
	}
	// a CLONE of the transcript, so a refusal below leaves this group's own transcript where the
	// epoch it is still in put it.
	transcript := self.transcript.Clone()
	if err := transcript.Update(self.crypto, confirmedInput, authenticated.Auth.ConfirmationTag); err != nil {
		return nil, err
	}

	// step 9: the new epoch's verified context, which is what the boundary owes the proposal cache,
	// and the secret tree the new epoch's messages ratchet out of.
	//
	// THIS CLIENT SIGNS THE GROUP INFO ITSELF, exactly as the creator does at epoch 0 and as
	// (*Group).CreateCommit does at every epoch after it. A commit carries no GroupInfo -- only a
	// Welcome does -- so there is no signature of the committer's over this context to verify, and
	// the authority the cache is owed is this client's own: it has just checked the confirmation
	// tag of the epoch it is about to enter, which is the strongest statement any member ever makes
	// about an epoch. A second door onto a verified context is what group_context_verified.go spent
	// four rounds establishing IS the defect, so the one door is used here too.
	groupInfo := &GroupInfo{
		GroupContext:    *newContext,
		ConfirmationTag: authenticated.Auth.ConfirmationTag,
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

	staged := &StagedCommit{
		committer:   committer,
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
		selfRemoved: false,
		hasPath:     commit.Path != nil,
		confirmTag:  authenticated.Auth.ConfirmationTag,
		restoreKind: restoreFromJoiner,
	}
	handedOn = true
	return staged, nil
}

// updatedOwnLeafPrivateLocked answers the private tree state this client holds AFTER a commit's
// proposals have been applied, or nil when they left this client's leaf alone.
//
// THE STATE IS FRESH AND CARRIES NO PATH SECRET, which is a consequence of section 12.1.2 rather
// than a simplification: an Update blanks the direct path of the leaf it replaces -- ApplyProposals
// says so and RatchetTree.UpdateLeaf does it -- so every rung this client held above that leaf is a
// secret for a node the commit blanked. Carrying them forward would leave a state whose held
// secrets name blank nodes, which is exactly what TreeKEMPrivate.Consistent refuses, and the rungs
// this client is entitled to are the ones the update path is about to hand it.
//
// The store's array is NOT erased here and is not the caller's to erase. GetPrivateKey answers
// whatever storage the implementation keeps -- the sdk writes these over its sealed local store --
// and NewTreeKEMPrivate copies what it is given, so an erase here would blank the entry this client
// may still need if the commit carrying it is refused further down and a later one carries it
// again. Deleting it is (StateStore).DeletePrivateKey's, on the epoch boundary task 19 owns.
func (self *Group) updatedOwnLeafPrivateLocked(applied *ApplyResult) (*TreeKEMPrivate, error) {
	// a spelled comparison of two leaf INDICES and not slices.Contains, which is what this
	// package's constant-time gate derives out of its own imports and refuses. That gate is about
	// comparisons of DATA and these are positions in a tree every member holds -- but the class it
	// derives is the comparator and not the operand, deliberately, and routing around a derived
	// class is the one thing standing rule 5 exists to prevent.
	updated := false
	for _, at := range applied.UpdatedLeaves {
		if at == self.ownLeaf {
			updated = true
		}
	}
	if !updated {
		return nil, nil
	}
	leaf := applied.Tree.Leaf(self.ownLeaf)
	if leaf == nil {
		return nil, fmt.Errorf("%w: this commit updates leaf %d and leaves it blank",
			ErrTreeMalformed, self.ownLeaf)
	}
	stored, err := self.store.GetPrivateKey(leaf.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("%w: leaf %d: %w", errUpdatedLeafPrivateKey, self.ownLeaf, err)
	}
	if len(stored) == 0 {
		return nil, fmt.Errorf("%w: leaf %d: the store answered no octets",
			errUpdatedLeafPrivateKey, self.ownLeaf)
	}
	return NewTreeKEMPrivate(self.ownLeaf, HpkePrivateKey(stored)), nil
}

// ApplyCommit promotes a staged inbound commit to live state.
//
// THE STAGED EPOCH THIS REPLACES IS ERASED BEFORE IT IS DROPPED, and that is the ordinary path
// rather than a cleanup one. A client that built its own commit and lost MASTER section 9.3's race
// is holding a fully derived epoch nobody ever entered -- its own key schedule, its own secret tree
// and the leaf key it drew for it -- and the peer's commit it is applying here is exactly what
// makes that epoch dead. After the assignment below nothing in this process can reach it.
//
// A COMMIT THAT REMOVES THIS CLIENT MERGES NOTHING. There is no epoch to enter: the staged value is
// the report stageInboundCommitLocked answers for that case, this group's own secrets are erased
// through Close, and the caller is told with ErrRemovedFromGroup rather than being handed a merge
// that silently produced a group this client is not a member of.
func (self *Group) ApplyCommit(processed *Processed) error {
	if processed == nil || processed.Kind != ProcessedCommit || processed.Commit == nil {
		return errApplyCommitNotACommit
	}
	self.stateLock.Lock()
	if self.closed {
		self.stateLock.Unlock()
		return errGroupClosed
	}
	if processed.Commit.RemovesSelf() {
		self.stateLock.Unlock()
		// Close erases this epoch's schedule, its secret tree, this leaf's private state, the
		// signing key and any commit still staged, and it is idempotent -- so a caller's own
		// deferred Close beside this one erases nothing twice.
		if err := self.Close(); err != nil {
			return err
		}
		return ErrRemovedFromGroup
	}
	self.pending.Zeroize()
	self.pending = processed.Commit
	self.stateLock.Unlock()
	return self.MergePendingCommit()
}

// Protect seals an application message under the current epoch.
//
// The AAD and the plaintext are the CALLER'S ARRAYS and nothing here retains either: both are read
// once, into the signature preimage and into the AEAD, and what leaves is the ciphertext. A caller
// that edits either after the call has changed nothing about the message it was handed.
func (self *Group) Protect(aad, plaintext []byte) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, errGroupClosed
	}
	groupContext, err := syntax.Marshal(self.context)
	if err != nil {
		return nil, err
	}
	content := &FramedContent{
		GroupId:           cloneBytes(self.context.GroupId),
		Epoch:             self.context.Epoch,
		Sender:            Sender{SenderType: SenderTypeMember, LeafIndex: self.ownLeaf},
		AuthenticatedData: aad,
		ContentType:       ContentTypeApplication,
		ApplicationData:   plaintext,
	}
	authenticated, err := SignAuthenticatedContent(self.crypto, self.signer,
		WireFormatPrivateMessage, content, groupContext)
	if err != nil {
		return nil, err
	}
	// LAST, because it is the first thing here that cannot be undone: the seal consumes a
	// generation of this leaf's ratchet whether or not the message is ever sent.
	private, err := SealPrivateMessage(self.crypto, self.secretTree,
		self.senderDataSecretLocked(), authenticated, PaddingSizeV1)
	if err != nil {
		return nil, err
	}
	return MarshalMLSMessage(&MLSMessage{
		Version:        ProtocolVersionMls10,
		WireFormat:     WireFormatPrivateMessage,
		PrivateMessage: private,
	})
}

// Unprotect opens an application message.
//
// It goes through ProcessMessage rather than calling OpenPrivateMessage itself, which is the whole
// reason it is six lines: the epoch check, the sender leaf check, the signature and the profile
// gate are stated once there, and a second receive path here would be a second answer to what this
// group accepts. What it adds is the refusal a caller asking for an application message needs -- a
// handshake message opened here is not a shorter answer, it is a different message, and by the time
// this returns a proposal it carried has already been cached.
func (self *Group) Unprotect(privateMessage []byte) (*ApplicationMessage, error) {
	processed, err := self.ProcessMessage(privateMessage)
	if err != nil {
		return nil, err
	}
	if processed.Kind != ProcessedApplication {
		return nil, fmt.Errorf("%w: this message was processed as kind %d",
			errApplicationMustBeCiphertext, processed.Kind)
	}
	return processed.Application, nil
}
