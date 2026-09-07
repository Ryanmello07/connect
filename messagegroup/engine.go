// Spec A section 6's narrow swappable interface, and the connect/mls adapter that satisfies it.
//
// The interface and the adapter share a file because section 2.2's tree pairs them, and they
// share a PACKAGE because EngineProcessed.stagedRef is unexported: an adapter that lived
// anywhere else could not put a staged commit in the one field section 6 calls unforgeable, so
// the two travel together or the argument is lost to a file move.
//
// It is declared HERE and not in connect/message. Section 12.1 gives the message server "no MLS
// type" and GroupHandle is twenty three of them; an interface whose whole subject is an MLS group,
// declared in the package the server links, is the shape the split exists to prevent.
//
// WHAT IS NOT ON THE INTERFACE IS THE WHOLE VALUE OF IT, quoted from section 6 because a later
// widening will be argued as a convenience:
//
//	Note what is not on this interface: no tree, no node, no secret tree, no HPKE, no
//	epoch_secret, no confirmation_key, no membership_key, no ciphersuite internals.
//	EngineProcessed.Raw and stagedRef are deliberately opaque so a staged commit can be carried
//	across a policy decision without connect/messagegroup being able to read or forge it.
//
// *mls.Group DOES NOT SATISFY GroupHandle and is not meant to. Thirteen of the twenty three
// methods cannot match -- OwnLeafIndex answers mls.LeafIndex where this answers uint32 and go
// method sets are identical-type rather than convertible-type; MemberAt takes a leaf and answers
// a Member where this takes an ordinal and answers three byte slices; MemberCount,
// SenderDataSecret, EncryptionSecret and ProposeGroupPolicy are absent; RatchetTreeSnapshot,
// GroupContextBytes, Commit and Process are named differently; ApplyCommit and Process name
// EngineProcessed, which is declared in THIS package and carries an unexported field, so no
// method of connect/mls can ever name it. That last pair is structurally unclosable BY DESIGN.
// The adapter below is what closes all thirteen, and every one of them is a decision it takes
// rather than a delegation it forwards.
//
// The type conversions all run in ONE direction at the boundary: a uint32 off the wire becomes an
// mls.LeafIndex here and nowhere else, so a raw index never reaches connect/mls unconverted.
package messagegroup

import (
	"fmt"

	"github.com/urnetwork/connect/mls"
	"github.com/urnetwork/connect/mls/syntax"
)

// GroupEngine is the factory half of section 6: everything a caller needs in order to obtain a
// GroupHandle, and nothing about a group it already holds.
//
// Four methods, transcribed from section 6's block. JoinFromWelcome is HERE and not on
// GroupHandle, which is worth stating because the other three of the four are obviously
// factories and this one reads like a group operation: a member joining from a Welcome has no
// handle yet, and putting it on the handle would require one to exist before the join that
// creates it.
type GroupEngine interface {
	Suite() uint16
	NewKeyPackage() (keyPackage []byte, err error)
	CreateGroup(groupId []byte, policy []byte, leafKeys []byte) (GroupHandle, error)
	JoinFromWelcome(welcome []byte, ratchetTree []byte) (GroupHandle, error)
}

// GroupHandle is the entire MLS surface the storage layer is allowed to see.
//
// Adding a method here is a design decision and not a convenience: everything on it is something
// a replacement implementation must provide, and engine_test.go holds the set to section 6's
// block by reading this file rather than by trusting this comment.
//
// Every signature names go types only. A method that named an mls type would make Gate 5's swap
// a type change rather than a factory change, and the interface would have stopped being a seam
// and become a re-export of connect/mls.
type GroupHandle interface {
	GroupId() []byte
	Epoch() uint64
	OwnLeafIndex() uint32
	MemberCount() int
	MemberAt(i int) (leafIndex uint32, identityPub []byte, leafKeys []byte, err error)

	// the two named secrets of MASTER section 8.2, and the exporter. Nothing else: EpochSecret
	// is deliberately absent, which is guardrail G6 seen from this side -- an accessor taking a
	// name would reach epoch_secret, confirmation_key and membership_key through the same door.
	Export(label string, context []byte, length int) ([]byte, error)
	SenderDataSecret() ([]byte, error)
	EncryptionSecret() ([]byte, error)
	EpochAuthenticator() []byte
	RatchetTreeSnapshot() ([]byte, error)
	GroupContextBytes() ([]byte, error)

	ProposeAdd(keyPackage []byte) ([]byte, error)
	ProposeRemove(leafIndex uint32) ([]byte, error)
	ProposeUpdate() ([]byte, error)
	ProposeGroupPolicy(policy []byte) ([]byte, error)

	Commit(byReference [][]byte) (commit []byte, welcome []byte, ratchetTree []byte, err error)
	MergePendingCommit() error
	ClearPendingCommit()

	Process(message []byte) (*EngineProcessed, error)
	ApplyCommit(processed *EngineProcessed) error

	Protect(aad []byte, plaintext []byte) ([]byte, error)
	Unprotect(message []byte) (aad []byte, plaintext []byte, senderLeaf uint32, err error)

	Close() error
}

// The three kinds Process discriminates, section 6's own numbering.
//
// They are declared as this package's constants rather than read off connect/mls's ProcessedKind
// because the field is a uint8 on an interface this package owns: a caller comparing against
// mls.ProcessedCommit would be naming an mls type through the seam, which is the one move the
// interface exists to prevent.
const (
	EngineProcessedApplication uint8 = 1
	EngineProcessedProposal    uint8 = 2
	EngineProcessedCommit      uint8 = 3
)

// EngineProcessed is one ingested MLS message as the storage layer is allowed to see it.
//
// Raw and stagedRef are both opaque and they are opaque for different reasons. Raw is opaque by
// CONTRACT -- nothing in this package may index, parse, compare or length check it, and
// engine_test.go derives the class of functions that read an EngineProcessed and holds every one
// of them to that. stagedRef is opaque by CONSTRUCTION: it is unexported, so only a member of
// this package can populate one, which is what makes a staged commit carried across a policy
// decision unforgeable BY THIS PACKAGE.
//
// The scope of that guarantee, stated because the loose reading of it has been wrong once. A
// keyed composite literal naming only the exported fields is legal across package boundaries, so
// a foreign engine may satisfy GroupHandle and return one of these; what it cannot do is put
// anything in stagedRef. The unforgeability therefore holds for engines declared in this
// package, and a foreign engine trades it for its independence. Open item M1-43.
type EngineProcessed struct {
	Kind       uint8
	SenderLeaf uint32
	Aad        []byte
	Plaintext  []byte
	// opaque to this package and handed back to ApplyCommit. It is the message these values
	// were read out of and nothing else; the staged commit is never here.
	Raw []byte
	// engine private. This package never inspects it, and no package but this one can write it.
	stagedRef any
}

// ---------------------------------------------------------------------------
// the connect/mls adapter
// ---------------------------------------------------------------------------

// The compile time assertions Task 9 could not make about *mls.Group, made about the type that is
// meant to have the property. A failure here is a build failure, which is the point: there is no
// state of this tree in which the adapter has stopped satisfying the interface and a test reports
// it later.
var (
	_ GroupEngine = (*connectMlsEngine)(nil)
	_ GroupHandle = (*connectMlsHandle)(nil)
)

// connectMlsEngine is the v1 engine: one identity, one crypto provider, one state store.
//
// It is unexported because the factory is the door. Gate 5's swap point is
// NewConnectMlsEngine's return type -- an interface -- and a caller holding the concrete type
// would be a caller the swap breaks.
type connectMlsEngine struct {
	crypto mls.CryptoProvider
	store  mls.StateStore
	signer mls.SignaturePrivateKey
	cred   mls.Credential
	// the encoded urmessage_leaf_keys body this device publishes: u16 alg_id followed by the
	// opaque X-Wing encapsulation key. It is held on the engine because section 6's
	// NewKeyPackage takes no arguments and a key package with no leaf keys extension is a leaf
	// no epoch fan out can ever wrap to.
	leafKeys []byte
}

// NewConnectMlsEngine builds the v1 engine over connect/mls.
//
// Everything it holds is injected, which is what makes the engine swappable at the factory: this
// function is the only place in the tree that names *mls.Group's neighbourhood on the way in.
//
// leafKeys is the ENCODED urmessage_leaf_keys body and is refused here rather than at the first
// group, because a device that cannot say what its wrap target key is has nothing to fix later:
// every group it creates would carry a leaf no device wrap can address.
func NewConnectMlsEngine(crypto mls.CryptoProvider, store mls.StateStore,
	signer mls.SignaturePrivateKey, cred mls.Credential, leafKeys []byte) (GroupEngine, error) {

	if crypto == nil {
		return nil, fmt.Errorf("%w: every secret this engine derives is drawn through it", ErrEngineCryptoProvider)
	}
	if store == nil {
		return nil, fmt.Errorf("%w: a group with nowhere to persist an epoch is a group that cannot be reopened", ErrEngineStateStore)
	}
	if len(signer) == 0 {
		return nil, fmt.Errorf("%w: the leaf of every group this engine founds is signed with it", ErrEngineSigner)
	}
	if _, err := mls.ParseLeafKeysExtension(leafKeys); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEngineLeafKeys, err)
	}
	return &connectMlsEngine{
		crypto: crypto,
		store:  store,
		// copies, because a caller's arrays are the caller's: a signer or a leaf keys body that
		// moved under this engine would sign one group's leaf with another group's key.
		signer:   append(mls.SignaturePrivateKey(nil), signer...),
		cred:     mls.BasicCredential(cred.Identity),
		leafKeys: append([]byte(nil), leafKeys...),
	}, nil
}

// Zeroize erases the identity signing key this engine holds a copy of.
//
// NOTHING IN THIS PACKAGE CALLS IT, and that is a gap in section 6 rather than an oversight here:
// GroupEngine has four methods and none of them is a lifecycle method, so an engine has no
// documented end. mls.Group clones the same signer into every group this device founds and erases
// its own copy at Close; this copy has no Close to be erased at. The erase is declared so the
// obligation sits on the type that holds the octets -- which is where connect/mls's erase reading
// puts it -- and so that whatever owns the engine has something to call the day section 6 grows
// one. It is reported as a finding of this batch rather than left as a comment.
//
//go:noinline
func (self *connectMlsEngine) Zeroize() {
	zeroize(self.signer)
}

// Suite is the ciphersuite the provider runs, as the code point rather than as mls.CipherSuite.
//
// The conversion is the seam. mls.CipherSuite is a defined type and a method answering it would
// put an mls type on the interface, which is the one thing section 6's block never does.
func (self *connectMlsEngine) Suite() uint16 {
	return uint16(self.crypto.Suite())
}

// NewKeyPackage mints and publishes one key package for this device, persisting the two private
// halves against its reference so that whoever admits this device can be answered.
//
// THE THIRD PRIVATE HALF IS NOT REACHABLE AND THAT IS WHY JoinFromWelcome REFUSES.
// mls.NewKeyPackage draws its own signature key pair and keeps the private half on an unexported
// field, and StateStore.PutKeyPackage carries only the init and encryption halves, so nothing
// outside package mls can assemble the mls.JoinKeyMaterial a Welcome join requires.
// JoinFromWelcome says so with a typed refusal rather than working around it: the two ways around
// are a second assembly of KeyPackageTBS and a second spelling of its signature label, and both
// are defect classes this tree has already paid for.
func (self *connectMlsEngine) NewKeyPackage() ([]byte, error) {
	leafKeys, err := mls.ParseLeafKeysExtension(self.leafKeys)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEngineLeafKeys, err)
	}
	leafKeysExtension, err := leafKeys.Encode()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEngineLeafKeys, err)
	}
	keyPackage, initPrivate, encryptPrivate, err := mls.NewKeyPackage(self.crypto, self.crypto.Suite(),
		self.cred, engineCapabilities(), []mls.Extension{leafKeysExtension})
	if err != nil {
		return nil, err
	}
	encoded, err := syntax.Marshal(keyPackage)
	if err != nil {
		return nil, err
	}
	ref, err := keyPackage.Ref(self.crypto)
	if err != nil {
		return nil, err
	}
	if err := self.store.PutKeyPackage(ref, encoded, initPrivate, encryptPrivate); err != nil {
		return nil, err
	}
	return encoded, nil
}

// CreateGroup founds a one member group with this device at leaf 0.
//
// policy is the encoded urmessage_group_policy body and leafKeys the encoded urmessage_leaf_keys
// body, both as opaque octets: section 6's signature takes bytes so that the storage layer never
// names an mls extension type, and the tagging is done here where the tag and the body are put
// together in one statement.
func (self *connectMlsEngine) CreateGroup(groupId []byte, policy []byte, leafKeys []byte) (GroupHandle, error) {
	parsedLeafKeys, err := mls.ParseLeafKeysExtension(leafKeys)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEngineLeafKeys, err)
	}
	group, err := mls.NewGroup(&mls.GroupConfig{
		Suite:   self.crypto.Suite(),
		GroupId: groupId,
		Extensions: []mls.Extension{{
			ExtensionType: mls.ExtensionTypeUrmessageGroupPolicy,
			ExtensionData: policy,
		}},
		RequiredCaps: engineRequiredCapabilities(),
		Crypto:       self.crypto,
		Store:        self.store,
		LeafKeys:     *parsedLeafKeys,
	}, self.signer, self.cred)
	if err != nil {
		return nil, err
	}
	return &connectMlsHandle{group: group}, nil
}

// JoinFromWelcome refuses, and the refusal names what is missing rather than describing it.
//
// mls.JoinFromWelcome requires an *mls.JoinKeyMaterial whose SignPrivate is the private half of
// the signature key the joiner's own published leaf names. mls.NewKeyPackage draws that key itself
// and keeps it on KeyPackage's unexported signPriv; mls.StateStore.TakeKeyPackage answers the key
// package, the init private half and the encryption private half and NOT that one; and no
// exported constructor of connect/mls mints a key package against a signature key its caller
// supplies. So this method cannot be written over today's exported surface of connect/mls at all.
//
// It fails CLOSED and it looks like what it is, which is this project's own rule about a missing
// key source: a join that returned a handle built out of a signature key this device does not
// hold would be a member every peer refuses, discovered at the first commit rather than here.
//
// It blocks wave 2 task 16 and it is reported as a finding of this batch rather than worked
// around here.
func (self *connectMlsEngine) JoinFromWelcome(welcome []byte, ratchetTree []byte) (GroupHandle, error) {
	// the two arguments are counted into the refusal rather than dropped, and that is not
	// decoration: a method that named neither of its parameters would be indistinguishable, to
	// every reading of the source, from a placeholder somebody meant to finish -- which is what
	// mls's own stub shape gate says about a body that is a function of less than it declares.
	// This one is a function of nothing on purpose, and the octet counts are what say so.
	return nil, fmt.Errorf("%w: connect/mls keeps a minted key package's signature private half on an unexported field and StateStore.TakeKeyPackage does not carry it, so the %d octet welcome and the %d octet ratchet tree cannot be joined from here",
		ErrEngineJoinUnavailable, len(welcome), len(ratchetTree))
}

// engineCapabilities is what every leaf this engine publishes advertises.
//
// Suites() rather than the one code point this engine runs, because the vector says what this
// device CAN do rather than what one group does: a leaf advertising only its own group's suite is
// a leaf no other suite could ever add. The two private use extension types are listed because
// every leaf carries urmessage_leaf_keys and every group context carries urmessage_group_policy,
// and RFC 9420 section 7.3 refuses a leaf that carries or meets a type it does not list.
//
// The proposal vector is empty and that is the CONFORMING answer rather than a gap: add, update
// and remove are section 7.2 default types, which section 7.2 forbids a leaf to list.
func engineCapabilities() mls.Capabilities {
	return mls.Capabilities{
		Versions:     []mls.ProtocolVersion{mls.ProtocolVersionMls10},
		CipherSuites: mls.Suites(),
		Extensions: []mls.ExtensionType{
			mls.ExtensionTypeUrmessageGroupPolicy,
			mls.ExtensionTypeUrmessageLeafKeys,
		},
		Proposals:   []mls.ProposalType{},
		Credentials: []mls.CredentialType{mls.CredentialTypeBasic},
	}
}

// engineRequiredCapabilities is what every group this engine founds requires of a joiner: the two
// private use extension types the profile puts on every leaf and every group context.
func engineRequiredCapabilities() mls.RequiredCapabilities {
	return mls.RequiredCapabilities{
		ExtensionTypes: []mls.ExtensionType{
			mls.ExtensionTypeUrmessageGroupPolicy,
			mls.ExtensionTypeUrmessageLeafKeys,
		},
	}
}

// connectMlsHandle wraps exactly one *mls.Group.
//
// It is the one production declaration in this package whose type mentions mls.Group, and
// engine_test.go derives that class off the syntax tree and holds it to this file BY SCANNED PATH
// rather than by base name -- a base name exemption is the exemption shape this project keeps
// rediscovering.
type connectMlsHandle struct {
	group *mls.Group
}

// GroupId is the group's identifier, as storage the caller owns: mls.Group already answers a copy.
func (self *connectMlsHandle) GroupId() []byte {
	return self.group.GroupId()
}

// Epoch is the epoch this handle is at.
func (self *connectMlsHandle) Epoch() uint64 {
	return self.group.Epoch()
}

// OwnLeafIndex is this device's leaf, converted out of mls.LeafIndex at the boundary.
//
// The conversion runs one way and only here. mls.LeafIndex is a defined type, so a widening of
// this result to it would make *mls.Group fit the interface -- which is the reshape section 6
// exists to refuse, because an interface that names mls's types is a re-export rather than a seam.
func (self *connectMlsHandle) OwnLeafIndex() uint32 {
	return uint32(self.group.OwnLeafIndex())
}

// MemberCount is how many members the group has.
func (self *connectMlsHandle) MemberCount() int {
	return len(self.group.Members())
}

// MemberAt projects one member down to section 6's three byte slices.
//
// i is an ORDINAL into the membership snapshot and not a leaf index, which is section 6's own
// signature: MemberCount and MemberAt are a pair, and a caller walking 0..MemberCount-1 must not
// have to know which leaves are blank.
//
// EVERY ABSENCE IS AN ERROR AND NEVER A ZERO VALUE. An ordinal off the end is a refusal, and a
// member whose leaf carries no urmessage_leaf_keys extension is a refusal too: a projection that
// answered a nil leafKeys would hand the epoch fan out a member it silently cannot wrap to, and a
// projection that dropped mls.MemberAt's bool would turn a missing member into leaf 0.
func (self *connectMlsHandle) MemberAt(i int) (uint32, []byte, []byte, error) {
	members := self.group.Members()
	if i < 0 || len(members) <= i {
		return 0, nil, nil, fmt.Errorf("%w: ordinal %d of %d members", ErrEngineMemberOrdinal, i, len(members))
	}
	member := members[i]
	if member.LeafKeys == nil {
		return 0, nil, nil, fmt.Errorf("%w: the member at ordinal %d carries no urmessage_leaf_keys extension",
			ErrEngineMemberLeafKeys, i)
	}
	leafKeys, err := member.LeafKeys.Encode()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%w: %w", ErrEngineMemberLeafKeys, err)
	}
	return uint32(member.LeafIndex), member.IdentityPub, leafKeys.ExtensionData, nil
}

// Export is RFC 9420 section 8.5's exporter, which MASTER section 7 derives mls_secret from.
//
// It is the one thing on this interface that reaches the epoch's secrets at all, and it reaches
// them through a label the caller names -- which is what keeps epoch_secret itself off the surface.
func (self *connectMlsHandle) Export(label string, context []byte, length int) ([]byte, error) {
	return self.group.Export(label, context, length)
}

// SenderDataSecret is MASTER section 8.2's sender_data secret.
//
// It names mls's closed EpochSecretName enum, and this file is the only place in the tree that
// names either constant. That is guardrail G6 seen from the client half: EpochSecret is not on
// GroupHandle precisely so epoch_secret, confirmation_key and membership_key cannot be reached
// from a package that holds the record keys.
func (self *connectMlsHandle) SenderDataSecret() ([]byte, error) {
	return self.group.EpochSecret(mls.EpochSecretSenderData)
}

// EncryptionSecret is MASTER section 8.2's encryption secret, through the same closed enum.
func (self *connectMlsHandle) EncryptionSecret() ([]byte, error) {
	return self.group.EpochSecret(mls.EpochSecretEncryption)
}

// EpochAuthenticator is the value two members compare to detect a fork, or nil for a closed group.
//
// Section 6 gives it no error and this adapter does not invent one: nil is mls's own answer for a
// closed group, and a nil authenticator compared against a nil authenticator is a comparison the
// caller has to refuse rather than a value this layer can improve.
func (self *connectMlsHandle) EpochAuthenticator() []byte {
	return self.group.EpochAuthenticator()
}

// RatchetTreeSnapshot is the encoded public tree, which MASTER section 8.2's per epoch snapshot
// record carries. The name is this plan's and mls's is RatchetTree; the divergence is naming only.
func (self *connectMlsHandle) RatchetTreeSnapshot() ([]byte, error) {
	return self.group.RatchetTree()
}

// GroupContextBytes is the serialized GroupContext for the current epoch. mls's name is
// GroupContext; the divergence is naming only, and the two bodies are NOT interchangeable even
// though both answer opaque octets.
func (self *connectMlsHandle) GroupContextBytes() ([]byte, error) {
	return self.group.GroupContext()
}

// ProposeAdd publishes an Add proposal for one encoded key package.
func (self *connectMlsHandle) ProposeAdd(keyPackage []byte) ([]byte, error) {
	return self.group.ProposeAdd(keyPackage)
}

// ProposeRemove publishes a Remove proposal for one leaf, converting at the boundary.
func (self *connectMlsHandle) ProposeRemove(leafIndex uint32) ([]byte, error) {
	return self.group.ProposeRemove(mls.LeafIndex(leafIndex))
}

// ProposeUpdate publishes an Update proposal for this device's own leaf.
func (self *connectMlsHandle) ProposeUpdate() ([]byte, error) {
	return self.group.ProposeUpdate()
}

// ProposeGroupPolicy publishes a GroupContextExtensions proposal carrying one policy body.
//
// This is the one method of the thirteen whose body is not a projection: mls takes a vector of
// tagged extensions and section 6 takes the body alone, so the 0xF001 tag is applied here. Pairing
// the body with the tag in one statement is what keeps a caller from pairing it with another.
func (self *connectMlsHandle) ProposeGroupPolicy(policy []byte) ([]byte, error) {
	return self.group.ProposeGroupContextExtensions([]mls.Extension{{
		ExtensionType: mls.ExtensionTypeUrmessageGroupPolicy,
		ExtensionData: policy,
	}})
}

// Commit builds a commit over the proposals named by reference, projecting *mls.CommitResult to
// section 6's three byte slices.
//
// The commit is STAGED and not merged. mls stages on both sides for the reason MASTER section 9.3
// gives: the delivery service accepts at most one commit per (group, epoch), so a committer that
// merged optimistically would fork itself off the group.
func (self *connectMlsHandle) Commit(byReference [][]byte) ([]byte, []byte, []byte, error) {
	result, err := self.group.CreateCommit(byReference, nil, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	return result.Commit, result.Welcome, result.RatchetTree, nil
}

// MergePendingCommit enters the epoch this handle's own staged commit opens.
func (self *connectMlsHandle) MergePendingCommit() error {
	return self.group.MergePendingCommit()
}

// ClearPendingCommit drops this handle's own staged commit.
func (self *connectMlsHandle) ClearPendingCommit() {
	self.group.ClearPendingCommit()
}

// Process ingests one MLS message, staging a commit rather than applying it.
//
// THE STAGED COMMIT GOES IN stagedRef AND NEVER IN Raw. Raw carries the message these values were
// read out of -- opaque octets, never inspected by this package -- and stagedRef carries the
// *mls.Processed together with the handle that staged it. Putting the staged value in Raw would
// hand this package a commit it could read and rebuild, which is exactly what section 6's
// unforgeability sentence is about.
func (self *connectMlsHandle) Process(message []byte) (*EngineProcessed, error) {
	processed, err := self.group.ProcessMessage(message)
	if err != nil {
		return nil, err
	}
	answer := &EngineProcessed{
		Kind: uint8(processed.Kind),
		// a copy, because the caller owns what it is handed and this package promises never
		// to look at it again.
		Raw:       append([]byte(nil), message...),
		stagedRef: &stagedProcessed{handle: self, processed: processed},
	}
	if processed.Kind == mls.ProcessedApplication {
		if processed.Application == nil {
			return nil, fmt.Errorf("%w: an application message with no application arm", ErrEngineProcessedArm)
		}
		answer.SenderLeaf = uint32(processed.Application.SenderLeaf)
		answer.Aad = processed.Application.AuthenticatedData
		answer.Plaintext = processed.Application.Plaintext
	}
	return answer, nil
}

// ApplyCommit enters the epoch a staged commit opens, and refuses anything this handle did not
// stage.
//
// The refusal is typed and is neither a panic nor a silent no-op. An EngineProcessed built by a
// keyed composite literal outside this package has a nil stagedRef -- that shape is legal go and
// section 6 says so -- and one staged by a DIFFERENT handle of this package carries another
// group's commit; both are refused here, so the guarantee is "the commit this handle staged" and
// not merely "some commit some engine staged".
func (self *connectMlsHandle) ApplyCommit(processed *EngineProcessed) error {
	if processed == nil {
		return fmt.Errorf("%w: no processed message", ErrEngineProcessedForeign)
	}
	staged, isStaged := processed.stagedRef.(*stagedProcessed)
	if !isStaged {
		return fmt.Errorf("%w: it carries no staged commit this engine put there", ErrEngineProcessedForeign)
	}
	if staged.handle != self {
		return fmt.Errorf("%w: it was staged by another handle", ErrEngineProcessedForeign)
	}
	return self.group.ApplyCommit(staged.processed)
}

// Protect seals one application message under the current epoch.
func (self *connectMlsHandle) Protect(aad []byte, plaintext []byte) ([]byte, error) {
	return self.group.Protect(aad, plaintext)
}

// Unprotect opens one application message, projecting *mls.ApplicationMessage to three values.
//
// The projection is total: mls answers an error for everything it refuses, and a nil message with
// a nil error is not a state mls can produce -- but it is refused here anyway, because the
// alternative to refusing it is three zero values that read as an empty message from leaf 0.
func (self *connectMlsHandle) Unprotect(message []byte) ([]byte, []byte, uint32, error) {
	application, err := self.group.Unprotect(message)
	if err != nil {
		return nil, nil, 0, err
	}
	if application == nil {
		return nil, nil, 0, fmt.Errorf("%w: an opened application message with no content", ErrEngineProcessedArm)
	}
	return application.AuthenticatedData, application.Plaintext, uint32(application.SenderLeaf), nil
}

// Close releases the group, erasing the epoch secrets it holds.
func (self *connectMlsHandle) Close() error {
	return self.group.Close()
}

// stagedProcessed is what this adapter puts in EngineProcessed.stagedRef: the mls value ApplyCommit
// needs, and the handle that staged it.
//
// The handle is in it because the mls value alone would let one group's staged commit be applied
// to another group's handle. mls would refuse it a step later, at the transcript; refusing it here
// names the mistake instead of naming a group nobody tampered with.
type stagedProcessed struct {
	handle    *connectMlsHandle
	processed *mls.Processed
}
