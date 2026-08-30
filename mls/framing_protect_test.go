// The RFC 9420 section 6.1 signature: what is in the preimage, what a verifier does with it,
// and the two ValSem codes that come out.
//
// Every refusal here is derived over the LENGTH or the SHAPE of the thing it alters rather
// than sampled at a position somebody chose, and that is not style. The three authentication
// bypasses this project has shipped were all found by something other than the test that was
// supposed to find them: a tag verifier reading the first byte of a 32 byte tag passed a test
// that flipped bit zero of byte zero, and a verifier accepting every truncation passed a suite
// with no length case in it at all. A sampled refusal states that ONE input is refused; the
// property is that every one is.
package mls

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// ---------------------------------------------------------------------------
// the values this file and the package's provider gates sign
// ---------------------------------------------------------------------------

// framingStubSignaturePriv is the seed every row of every gate in this package signs a framed
// content with. One value rather than one per row, so a row that reads the wrong key is not
// answered by a neighbour's.
func framingStubSignaturePriv() SignaturePrivateKey {
	return SignaturePrivateKey(bytes.Repeat([]byte{0x5d}, 32))
}

// framingStubFramedContent is a member's application message with every byte carrying field
// populated.
//
// Every field carries something on purpose. A preimage that dropped one is invisible when that
// field is empty to begin with, and the stub gate's zero-answer report reads the byte fields
// of the AuthenticatedContent this is signed into -- so an empty one there would be reported
// as the stub it is not.
func framingStubFramedContent() *FramedContent {
	return framingStubFramedContentOver(func(content []byte) []byte { return content })
}

// The same content with every array it carries taken through a caller's hook, which is what
// lets the aliasing gate see the arrays a signature was built over.
func framingStubFramedContentOver(take func(content []byte) []byte) *FramedContent {
	return &FramedContent{
		GroupId:           take([]byte{0x11, 0x12, 0x13, 0x14}),
		Epoch:             7,
		Sender:            Sender{SenderType: SenderTypeMember, LeafIndex: 2},
		AuthenticatedData: take([]byte{0x21, 0x22}),
		ContentType:       ContentTypeApplication,
		ApplicationData:   take([]byte("the payload a framed content carries")),
	}
}

// framingStubGroupContext is a serialized GroupContext for the gates that sign one in.
//
// It is built through this package's own codec and at the PROVIDER's own hash width, rather
// than being a run of bytes this file chose. The width is what makes it usable by the KDF.Nh
// differential: a group context whose hashes were a written down 32 octets would be the same
// bytes over a provider whose KDF.Nh is 48, and the row would state nothing about the width
// the caller is running at.
func framingStubGroupContext(t *testing.T, crypto CryptoProvider) []byte {
	t.Helper()
	encoded, err := syntax.Marshal(&GroupContext{
		Version:                 ProtocolVersionMls10,
		CipherSuite:             crypto.Suite(),
		GroupId:                 []byte{0x11, 0x12, 0x13, 0x14},
		Epoch:                   7,
		TreeHash:                bytes.Repeat([]byte{0x92}, crypto.HashSize()),
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0x93}, crypto.HashSize()),
	})
	if err != nil {
		t.Fatalf("encode the group context these signatures are bound to: %v", err)
	}
	return encoded
}

// providerStubFramingArguments fills in the arguments the package's provider gates call
// SignAuthenticatedContent and VerifyAuthenticatedContent with.
//
// It lives here rather than in crypto_test.go for the reason the psk list's and the leaf's
// values do: nothing there knows how to build a FramedContent that encodes, and the verify row
// needs a message that has ACTUALLY been signed rather than one that resembles a signed one --
// a base call that refused would leave every perturbation below it comparing one refusal
// against another and reporting a complete implementation as observing all of its inputs.
//
// The group context is the one the rest of that gate's rows are built over, serialized, so a
// construction that read the epoch out of it is moved by the same perturbation that moves it
// for the key schedule.
func providerStubFramingArguments(t *testing.T, fixture CryptoProvider, priv SignaturePrivateKey,
	groupContext *GroupContext, arguments map[string]any) {

	t.Helper()
	encodedGroupContext, err := syntax.Marshal(groupContext)
	if err != nil {
		t.Fatalf("encode the group context the framing rows are built over: %v", err)
	}
	arguments["WireFormat"] = WireFormatPrivateMessage
	arguments["*FramedContent"] = framingStubFramedContent()
	arguments["SignAuthenticatedContent.groupContext"] = encodedGroupContext
	arguments["VerifyAuthenticatedContent.groupContext"] = encodedGroupContext
	signed, err := SignAuthenticatedContent(fixture, priv, WireFormatPrivateMessage,
		framingStubFramedContent(), encodedGroupContext)
	if err != nil {
		t.Fatalf("sign the message the VerifyAuthenticatedContent row reads: %v", err)
	}
	arguments["VerifyAuthenticatedContent.authContent"] = signed

	// the membership tag pair. The key is at the provider's own hash width rather than a
	// written down 32 octets, for framingStubGroupContext's reason: a key whose length was a
	// constant would be the same bytes over a provider whose KDF.Nh is 48, and the rows built
	// on it would state nothing about the width the caller is running at.
	membershipKey := bytes.Repeat([]byte{0x6b}, fixture.HashSize())
	arguments["ComputeMembershipTag.membershipKey"] = membershipKey
	arguments["ComputeMembershipTag.authContent"] = signed
	arguments["ComputeMembershipTag.groupContext"] = encodedGroupContext
	arguments["verifyMembershipTag.membershipKey"] = membershipKey
	arguments["verifyMembershipTag.authContent"] = signed
	arguments["verifyMembershipTag.groupContext"] = encodedGroupContext
	// the tag the verify row is handed has to be a REAL one over these arguments, for the
	// reason the signature above is: a base call that refused would leave every perturbation
	// below it comparing one refusal against another and reporting a verifier that reads none
	// of its inputs as observing all of them.
	tag, err := ComputeMembershipTag(fixture, membershipKey, signed, encodedGroupContext)
	if err != nil {
		t.Fatalf("compute the membership tag the verify row reads: %v", err)
	}
	arguments["verifyMembershipTag.tag"] = tag

	// section 6.2's seal and open. Both rows need a base call that SUCCEEDS, for the reason the
	// tag above is a real one: a base call that refused would leave every perturbation below it
	// comparing one refusal against another, and would report a construction that reads none of
	// its inputs as one that observes all of them.
	//
	// The content is a PROPOSAL and not the application message the rows above are built over,
	// because ValSem005 refuses an application message in a public frame -- that is the rule these
	// two exist to hold, not a shape they can be measured through. It is signed under
	// WireFormatPublicMessage, because the wire format is inside the signature preimage and the
	// seal refuses any other; and its sender is a member, because that is the arm section 6.2
	// gives a membership tag and therefore the only arm in which the membership key is read at all.
	sealContent := framingStubFramedContent()
	sealContent.ContentType = ContentTypeProposal
	sealContent.ApplicationData = nil
	sealContent.Proposal = &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 5}}
	sealed, err := SignAuthenticatedContent(fixture, priv, WireFormatPublicMessage,
		sealContent, encodedGroupContext)
	if err != nil {
		t.Fatalf("sign the message the SealPublicMessage row reads: %v", err)
	}
	arguments["SealPublicMessage.membershipKey"] = membershipKey
	arguments["SealPublicMessage.authContent"] = sealed
	arguments["SealPublicMessage.groupContext"] = encodedGroupContext
	message, err := SealPublicMessage(fixture, membershipKey, sealed, encodedGroupContext)
	if err != nil {
		t.Fatalf("seal the message the OpenPublicMessage row reads: %v", err)
	}
	pub, isKey := arguments["SignaturePublicKey"].(SignaturePublicKey)
	if !isKey {
		t.Fatal("the stub arguments hold no signature public key, so the open row has no resolver to build")
	}
	arguments["OpenPublicMessage.membershipKey"] = membershipKey
	arguments["OpenPublicMessage.message"] = message
	arguments["OpenPublicMessage.resolve"] = StaticSignatureKey(pub)
	arguments["OpenPublicMessage.groupContext"] = encodedGroupContext

	// section 6.3.2's seal and open. The open's row needs a base call that SUCCEEDS, for the
	// reason section 6.2's does: a base call that refused would leave every perturbation below
	// it comparing one refusal against another, and would report a construction that reads none
	// of its inputs as one that observes all of them.
	//
	// The secret is at the provider's own hash width rather than a written down 32 octets, for
	// the membership key's reason above, and because SenderDataKeyNonce refuses every other
	// length -- a refused call is a row that observed nothing.
	//
	// The CIPHERTEXT is exactly KDF.Nh, which is SenderDataKeyNonce.ciphertext's choice and is
	// made here for that argument's reason. RFC 9420 section 6.3.2 samples the first KDF.Nh
	// octets and no more, so a longer ciphertext would put the middle and last perturbations
	// outside the sample -- where an answer that does not move is the RFC working rather than a
	// stub, and would be reported as "does not read the ciphertext it was handed". Where the
	// sample boundary is held instead is
	// TestTheSenderDataSampleLocatesBothItsOffsetAndItsLength.
	senderDataSecret := bytes.Repeat([]byte{0x6d}, fixture.HashSize())
	senderDataCiphertext := bytes.Repeat([]byte{0x6e}, fixture.HashSize())
	senderDataHeader := &PrivateMessage{
		GroupId:           []byte{0x11, 0x12},
		Epoch:             4,
		ContentType:       ContentTypeApplication,
		AuthenticatedData: []byte{0x13},
	}
	// every field carries something, so a perturbation has a field to move and a seal that
	// dropped one is not hidden by that field being zero to begin with.
	senderData := &SenderData{LeafIndex: 2, Generation: 5, ReuseGuard: [4]byte{0x21, 0x22, 0x23, 0x24}}
	arguments["sealSenderData.senderDataSecret"] = senderDataSecret
	arguments["sealSenderData.senderData"] = senderData
	arguments["sealSenderData.header"] = senderDataHeader
	arguments["sealSenderData.ciphertext"] = senderDataCiphertext
	encryptedSenderData, err := sealSenderData(fixture, senderDataSecret, senderData,
		senderDataHeader, senderDataCiphertext)
	if err != nil {
		t.Fatalf("seal the sender data the openSenderData row reads: %v", err)
	}
	arguments["openSenderData.senderDataSecret"] = senderDataSecret
	arguments["openSenderData.encryptedSenderData"] = encryptedSenderData
	arguments["openSenderData.header"] = senderDataHeader
	arguments["openSenderData.ciphertext"] = senderDataCiphertext
}

// providerPublicMessagePerturbations moves the epoch of the message being opened.
//
// It is providerAuthenticatedContentPerturbations' rule and it is here for that rule's reason,
// with one more consequence: BOTH authenticators travel with the value unchanged, so what this
// asks is whether the open rebuilt both preimages out of the message it was handed. An open that
// checked either authenticator against anything but a preimage over these bytes answers the same
// thing twice.
func providerPublicMessagePerturbations(t *testing.T, operation string, parameter providerParameter,
	argument reflect.Value) []providerPerturbation {

	t.Helper()
	base := argument.Interface().(*PublicMessage)
	if base == nil {
		t.Fatalf("the base argument for %s.%s is a nil public message, so perturbing it changes nothing",
			operation, parameter.name)
	}
	moved := *base
	moved.Content.Epoch++
	return []providerPerturbation{{where: "epoch one higher", value: reflect.ValueOf(&moved)}}
}

// providerSignatureKeyResolverPerturbations answers a resolver that hands back a DIFFERENT key.
//
// The resolver is the one argument of the open that is not bytes, and what it decides is whose
// signature the message is checked against -- the whole of ValSem010 at this layer. An open whose
// answer did not reach the verification would accept any member's message under any other
// member's leaf, so what is moved is the ANSWER and not the shape: the base resolver's own key
// with a byte flipped, which is a key nothing ever signed with.
//
// The positions come off the key's length rather than being written down, which is
// perturbedPositions' rule: moving only the last byte states that the last byte is read.
func providerSignatureKeyResolverPerturbations(t *testing.T, operation string, parameter providerParameter,
	argument reflect.Value) []providerPerturbation {

	t.Helper()
	base, isResolver := argument.Interface().(SignatureKeyResolver)
	if !isResolver || base == nil {
		t.Fatalf("the base argument for %s.%s is not a resolver, so perturbing it changes nothing",
			operation, parameter.name)
	}
	answered, err := base(Sender{SenderType: SenderTypeMember})
	if err != nil {
		t.Fatalf("the base resolver for %s.%s refused: %v", operation, parameter.name, err)
	}
	if len(answered) == 0 {
		t.Fatalf("the base resolver for %s.%s answers no key, so a flipped one is not a different one",
			operation, parameter.name)
	}
	moved := []providerPerturbation{}
	for _, at := range perturbedPositions(len(answered)) {
		flipped := append([]byte(nil), answered...)
		flipped[at] ^= 0xff
		moved = append(moved, providerPerturbation{
			where: fmt.Sprintf("the key it answers, byte %d of %d", at, len(answered)),
			value: reflect.ValueOf(StaticSignatureKey(SignaturePublicKey(flipped))),
		})
	}
	return moved
}

// providerFramedContentPerturbations moves the epoch of a framed content and nothing else.
//
// The epoch for the reason the group context's own rule moves the epoch: it is the field two
// messages of one group differ in, it is inside the preimage on every path, and a construction
// that dropped the content out of what it signed answers identically here while one that kept
// it cannot. The copy is made field by field through a fresh value rather than by taking the
// address of a struct copy, so this perturbation cannot write through into the base argument
// every other row is built from.
func providerFramedContentPerturbations(t *testing.T, operation string, parameter providerParameter,
	argument reflect.Value) []providerPerturbation {

	t.Helper()
	base := argument.Interface().(*FramedContent)
	if base == nil {
		t.Fatalf("the base argument for %s.%s is a nil framed content, so perturbing it changes nothing",
			operation, parameter.name)
	}
	moved := *base
	moved.Epoch++
	return []providerPerturbation{{where: "epoch one higher", value: reflect.ValueOf(&moved)}}
}

// providerAuthenticatedContentPerturbations moves the epoch of the message being verified, for
// the reason above and with one extra consequence worth stating: the signature travels with the
// value unchanged, so what this asks is whether the verifier rebuilt its preimage out of the
// message it was handed. A verifier that had cached, or that compared the signature against
// anything but a preimage over these bytes, answers the same thing twice.
func providerAuthenticatedContentPerturbations(t *testing.T, operation string, parameter providerParameter,
	argument reflect.Value) []providerPerturbation {

	t.Helper()
	base := argument.Interface().(*AuthenticatedContent)
	if base == nil {
		t.Fatalf("the base argument for %s.%s is a nil authenticated content, so perturbing it changes nothing",
			operation, parameter.name)
	}
	moved := *base
	moved.Content.Epoch++
	return []providerPerturbation{{where: "epoch one higher", value: reflect.ValueOf(&moved)}}
}

// providerSenderDataPerturbations moves the GENERATION of the sender data being sealed.
//
// The generation and not the leaf index, for one reason that is worth writing down: the two are
// adjacent uint32s in section 6.3.2's structure, so a codec that swapped them agrees with itself
// and a perturbation of either moves the answer just the same. What this row asks is only whether
// the seal put the sender data into the plaintext AT ALL -- a seal that sealed a constant, or that
// sealed its header twice, answers identically here and one that carried the caller's value
// cannot. Which field goes where is TestSenderDataRoundTrip's golden.
func providerSenderDataPerturbations(t *testing.T, operation string, parameter providerParameter,
	argument reflect.Value) []providerPerturbation {

	t.Helper()
	base := argument.Interface().(*SenderData)
	if base == nil {
		t.Fatalf("the base argument for %s.%s is a nil sender data, so perturbing it changes nothing",
			operation, parameter.name)
	}
	moved := *base
	moved.Generation++
	return []providerPerturbation{{where: "generation one higher", value: reflect.ValueOf(&moved)}}
}

// providerPrivateMessagePerturbations moves the epoch of the cleartext header, which is the field
// two messages of one group differ in and is inside section 6.3.2's associated data.
//
// The header is not encrypted and is not the plaintext: what a seal or an open does with it is
// build the AAD, so an operation that dropped it out of that AAD answers identically here and one
// that kept it cannot. The copy is a struct copy whose byte fields are read and never written, so
// this perturbation cannot reach into the base argument every other row is built from.
func providerPrivateMessagePerturbations(t *testing.T, operation string, parameter providerParameter,
	argument reflect.Value) []providerPerturbation {

	t.Helper()
	base := argument.Interface().(*PrivateMessage)
	if base == nil {
		t.Fatalf("the base argument for %s.%s is a nil private message header, so perturbing it changes nothing",
			operation, parameter.name)
	}
	moved := *base
	moved.Epoch++
	return []providerPerturbation{{where: "epoch one higher", value: reflect.ValueOf(&moved)}}
}

// ---------------------------------------------------------------------------
// the preimage
// ---------------------------------------------------------------------------

// emptyByteSpelling is one way a caller can hand this package a byte slice of length zero.
type emptyByteSpelling struct {
	what  string
	value []byte
}

// emptyByteSpellings is EVERY such way, which is three and not the one a guard's author
// pictures.
//
// A rule about an absent value has to be written on the LENGTH, and these three separate it
// from the two things it can be written on by mistake. nil is the zero value a fresh struct
// field carries; the empty literal is non nil with no capacity, which is what syntax.Marshal
// of nothing and a caller's []byte{} both answer; and a slice re-sliced to nothing out of a
// longer buffer is non nil WITH capacity, which is what a decoder hands back after reading an
// empty opaque<V>. A guard spelled == nil accepts the last two and one spelled on cap accepts
// the first two; only one spelled on len refuses all three.
//
// Measured rather than supposed. With the preimage's binding guard rewritten from
// len(self.GroupContext) == 0 to self.GroupContext == nil -- which signs an epoch UNBOUND
// preimage for a member handed an empty non nil context, the signature valid in every epoch
// of the group that senderBindsGroupContext names as the most expensive omission available
// here -- and with ValSem009's tag guard rewritten the same way, this package's whole suite
// passed both times.
func emptyByteSpellings() []emptyByteSpelling {
	return []emptyByteSpelling{
		{what: "nil", value: nil},
		{what: "the empty literal", value: []byte{}},
		{what: "re-sliced to nothing out of a longer buffer", value: make([]byte, 0, 8)},
	}
}

// framingTestGroupContext is a real serialized GroupContext, built the way every caller must
// build one: syntax.Marshal over the key schedule's structure. The preimage inlines these bytes
// verbatim, with no length prefix.
func framingTestGroupContext(t *testing.T) []byte {
	t.Helper()
	encoded, err := syntax.Marshal(&GroupContext{
		Version:                 ProtocolVersionMls10,
		CipherSuite:             CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:                 []byte{0x01, 0x02},
		Epoch:                   4,
		TreeHash:                bytes.Repeat([]byte{0xc0}, 32),
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0xee}, 32),
	})
	if err != nil {
		t.Fatalf("group context: %v", err)
	}
	return encoded
}

func framingTestMemberContent() *FramedContent {
	return &FramedContent{
		GroupId:           []byte{0x01, 0x02},
		Epoch:             4,
		Sender:            Sender{SenderType: SenderTypeMember, LeafIndex: 1},
		AuthenticatedData: []byte{0x09},
		ContentType:       ContentTypeApplication,
		ApplicationData:   []byte("payload"),
	}
}

func framingTestProposalContent() *FramedContent {
	content := framingTestMemberContent()
	content.ContentType = ContentTypeProposal
	content.ApplicationData = nil
	content.Proposal = &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 3}}
	return content
}

func framingTestCommitContent() *FramedContent {
	content := framingTestMemberContent()
	content.ContentType = ContentTypeCommit
	content.ApplicationData = nil
	content.Commit = &Commit{}
	return content
}

// TestFramedContentTBSInlinesGroupContextWithoutLengthPrefix holds the layout against an
// encoder written out here rather than against the one under test.
//
// The group context is the field this exists for. It is a STRUCT in RFC 9420's presentation
// language and not an opaque<V>, so it carries no length prefix -- and a preimage that added
// one is a signature this package verifies against itself perfectly, since both halves would
// add it, and every other implementation rejects. Nothing round trips through a
// FramedContentTBS, so no symmetry property in this package can see the substitution.
//
// The table runs every content type and both group context arms rather than one row, because
// the layout is where the arms differ: the version and wire format are two uint16s, the content
// is whatever its own codec writes, and the context is either the whole of the tail or absent.
//
// The byte equality is the WHOLE of each row and nothing stands after it, which is a deletion
// from the version this task was handed rather than an omission. That version closed with
// bytes.HasSuffix(tbs, groupContext) after the equality had already passed, and an assertion
// reached only once the bytes are known to equal an encoding that ends in those same bytes is
// an assertion no implementation can fail -- decoration that reads as a second check. The same
// went for every restatement tried here: once a preimage is compared against a full independent
// encoding, every property of it is settled.
//
// What that equality cannot do is notice a hand written encoder in this file that is wrong the
// same way the implementation is wrong. Nothing in this package can; what can is
// TestTheFramedContentSignatureIsTheOneMlswgPublished, which compares against signatures
// somebody else made. The two are meant to be read together -- this one localises a failure to
// a field, and that one is the reason to believe the layout at all.
func TestFramedContentTBSInlinesGroupContextWithoutLengthPrefix(t *testing.T) {
	groupContext := framingTestGroupContext(t)
	external := framingTestProposalContent()
	external.Sender = Sender{SenderType: SenderTypeExternal, SenderIndex: 0}
	for _, testCase := range []struct {
		name         string
		wireFormat   WireFormat
		content      *FramedContent
		groupContext []byte
	}{
		{name: "a member's application message", wireFormat: WireFormatPrivateMessage,
			content: framingTestMemberContent(), groupContext: groupContext},
		{name: "a member's proposal", wireFormat: WireFormatPublicMessage,
			content: framingTestProposalContent(), groupContext: groupContext},
		{name: "a member's commit", wireFormat: WireFormatPublicMessage,
			content: framingTestCommitContent(), groupContext: groupContext},
		{name: "an external sender's proposal", wireFormat: WireFormatPublicMessage,
			content: external, groupContext: nil},
	} {
		tbs, err := FramedContentTBSBytes(testCase.wireFormat, testCase.content, testCase.groupContext)
		if err != nil {
			t.Errorf("%s: tbs: %v", testCase.name, err)
			continue
		}
		w := syntax.NewWriter()
		w.WriteUint16(uint16(ProtocolVersionMls10))
		w.WriteUint16(uint16(testCase.wireFormat))
		if err := testCase.content.MarshalMLS(w); err != nil {
			t.Errorf("%s: content: %v", testCase.name, err)
			continue
		}
		w.WriteRaw(testCase.groupContext)
		want, err := w.Bytes()
		if err != nil {
			t.Errorf("%s: bytes: %v", testCase.name, err)
			continue
		}
		if !bytes.Equal(tbs, want) {
			t.Errorf("%s: tbs %x, want %x", testCase.name, tbs, want)
		}
	}
}

func TestFramedContentTBSOmitsGroupContextForExternalSender(t *testing.T) {
	content := framingTestProposalContent()
	content.Sender = Sender{SenderType: SenderTypeExternal, SenderIndex: 0}

	tbs, err := FramedContentTBSBytes(WireFormatPublicMessage, content, nil)
	if err != nil {
		t.Fatalf("tbs: %v", err)
	}
	if bytes.Contains(tbs, framingTestGroupContext(t)) {
		t.Fatal("group context present for an external sender")
	}
	_, err = FramedContentTBSBytes(WireFormatPublicMessage, content, framingTestGroupContext(t))
	if !errors.Is(err, ErrUnexpectedGroupContext) {
		t.Fatalf("got %v, want ErrUnexpectedGroupContext", err)
	}
}

// Over every spelling of an absent group context rather than the nil one alone, which is what
// this test's name claims and what a guard written on the pointer does not hold: a member
// handed an empty non nil context would sign a preimage carrying no epoch at all.
func TestFramedContentTBSRequiresGroupContextForMember(t *testing.T) {
	for _, empty := range emptyByteSpellings() {
		_, err := FramedContentTBSBytes(WireFormatPrivateMessage, framingTestMemberContent(), empty.value)
		if !errors.Is(err, ErrMissingGroupContext) {
			t.Fatalf("a group context that is %s: got %v, want ErrMissingGroupContext", empty.what, err)
		}
	}
}

// rfc9420SendersThatBindTheGroupContext is RFC 9420 section 6.1's select on sender_type, keyed
// by the RFC's own spelling of each arm.
//
// Read off the RFC rather than off senderBindsGroupContext, which is the only thing that can
// make the test below an assertion: a table derived from the function under test agrees with
// whatever that function does.
var rfc9420SendersThatBindTheGroupContext = map[string]bool{
	"member":              true,
	"external":            false,
	"new_member_proposal": false,
	"new_member_commit":   true,
}

// TestEverySenderTypeBindsTheGroupContextSection61GivesIt joins that table against the registry
// this package declares, in both directions, and then against the BEHAVIOUR rather than against
// the switch.
//
// Derived rather than listed for the reason every sweep in framing_test.go is: a fifth sender
// type declared and left out of a hand written list is a sender type nothing here judges, and
// this is the rule that decides whether a signature is bound to an epoch at all. An omission
// here is a message replayable into every later epoch of the group.
func TestEverySenderTypeBindsTheGroupContextSection61GivesIt(t *testing.T) {
	derived := registryConstantsOfType(t, "SenderType")
	if len(derived) == 0 {
		t.Fatal("no SenderType constant was derived, so this gate runs over the empty set")
	}
	measured := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(derived)) {
		senderType := SenderType(derived[name])
		binds, err := senderBindsGroupContext(senderType)
		if err != nil {
			t.Errorf("%s is a registered sender type and senderBindsGroupContext refused it: %v", name, err)
			continue
		}
		measured[rfcNameOfFramingConstant("SenderType", name)] = binds
		// and the same answer read off the preimage rather than off the helper, so a
		// MarshalMLS that stopped consulting it is reported here as well
		content := framingTestProposalContent()
		content.Sender = Sender{SenderType: senderType}
		_, withContext := FramedContentTBSBytes(WireFormatPublicMessage, content, framingTestGroupContext(t))
		if binds && withContext != nil {
			t.Errorf("%s binds the group context and the preimage refused one: %v", name, withContext)
		}
		if !binds && !errors.Is(withContext, ErrUnexpectedGroupContext) {
			t.Errorf("%s binds no group context and the preimage answered %v to one", name, withContext)
		}
		// the absent direction over EVERY spelling of absent rather than over nil alone.
		// The two arms do not cost the same thing when a guard is spelled on the pointer:
		// a sender that binds the context and was handed an empty non nil one would sign a
		// preimage with no epoch in it, which is a signature valid in every epoch this
		// group ever has.
		for _, empty := range emptyByteSpellings() {
			_, withoutContext := FramedContentTBSBytes(WireFormatPublicMessage, content, empty.value)
			if binds && !errors.Is(withoutContext, ErrMissingGroupContext) {
				t.Errorf("%s binds the group context and the preimage answered %v to one that is %s",
					name, withoutContext, empty.what)
			}
			if !binds && withoutContext != nil {
				t.Errorf("%s binds no group context and the preimage refused one that is %s: %v",
					name, empty.what, withoutContext)
			}
		}
	}
	if !maps.Equal(measured, rfc9420SendersThatBindTheGroupContext) {
		t.Errorf("this package binds the group context for\n %v\nand RFC 9420 section 6.1's select gives\n %v",
			measured, rfc9420SendersThatBindTheGroupContext)
	}
}

// ---------------------------------------------------------------------------
// sign and verify
// ---------------------------------------------------------------------------

// framingSigned is one signed message together with everything needed to check it, built once
// per test so that each test varies one thing rather than declaring a slightly different value.
type framingSigned struct {
	crypto       CryptoProvider
	priv         SignaturePrivateKey
	pub          SignaturePublicKey
	groupContext []byte
	authContent  *AuthenticatedContent
}

func framingSignedMemberMessage(t *testing.T) framingSigned {
	t.Helper()
	crypto := newTestCrypto(t)
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	groupContext := framingTestGroupContext(t)
	authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPrivateMessage,
		framingTestMemberContent(), groupContext)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return framingSigned{crypto: crypto, priv: priv, pub: pub,
		groupContext: groupContext, authContent: authContent}
}

func TestSignAndVerifyAuthenticatedContent(t *testing.T) {
	signed := framingSignedMemberMessage(t)
	if err := VerifyAuthenticatedContent(signed.crypto, signed.pub, signed.authContent, signed.groupContext); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestSignAuthenticatedContentLeavesTheConfirmationTagToItsCaller states the half of this
// constructor's contract that has no signature in it.
//
// The empty confirmation tag is the SHAPE and not an omission: section 8.2 takes the confirmed
// transcript hash over this signature and the tag is a MAC over that hash, so the tag cannot
// exist yet. A constructor that filled one in would be filling in a value derived from a
// transcript that has not been advanced, which every peer would compute differently.
func TestSignAuthenticatedContentLeavesTheConfirmationTagToItsCaller(t *testing.T) {
	signed := framingSignedMemberMessage(t)
	if len(signed.authContent.Auth.ConfirmationTag) != 0 {
		t.Errorf("the signer produced a confirmation tag %x", signed.authContent.Auth.ConfirmationTag)
	}
	if signed.authContent.WireFormat != WireFormatPrivateMessage {
		t.Errorf("the signer carried the wire format %d and it was handed %d",
			signed.authContent.WireFormat, WireFormatPrivateMessage)
	}
	if !reflect.DeepEqual(&signed.authContent.Content, framingTestMemberContent()) {
		t.Errorf("the signer carried a content that is not the one it was handed")
	}
	if len(signed.authContent.Auth.Signature) == 0 {
		t.Error("the signer produced no signature at all")
	}
}

func TestAuthenticatedContentRefusesForgedSignature(t *testing.T) {
	signed := framingSignedMemberMessage(t)

	tampered := *signed.authContent
	tampered.Auth.Signature = append([]byte(nil), signed.authContent.Auth.Signature...)
	tampered.Auth.Signature[0] ^= 0x01
	if err := VerifyAuthenticatedContent(signed.crypto, signed.pub, &tampered, signed.groupContext); !errors.Is(err, errBadSignature) {
		t.Fatalf("flipped signature: got %v, want the ValSem010 sentinel", err)
	}

	empty := *signed.authContent
	empty.Auth.Signature = nil
	if err := VerifyAuthenticatedContent(signed.crypto, signed.pub, &empty, signed.groupContext); !errors.Is(err, errBadSignature) {
		t.Fatalf("empty signature: got %v, want the ValSem010 sentinel", err)
	}

	otherContext := append([]byte(nil), signed.groupContext...)
	otherContext[0] ^= 0xff
	if err := VerifyAuthenticatedContent(signed.crypto, signed.pub, signed.authContent, otherContext); !errors.Is(err, errBadSignature) {
		t.Fatalf("wrong group context: got %v, want the ValSem010 sentinel", err)
	}

	rewired := *signed.authContent
	rewired.WireFormat = WireFormatPublicMessage
	if err := VerifyAuthenticatedContent(signed.crypto, signed.pub, &rewired, signed.groupContext); !errors.Is(err, errBadSignature) {
		t.Fatalf("rewired wire format: got %v, want the ValSem010 sentinel", err)
	}

	// and the wrong key, which is the one refusal above that is not about the message
	_, otherPub, err := signed.crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("a second key pair: %v", err)
	}
	if err := VerifyAuthenticatedContent(signed.crypto, otherPub, signed.authContent, signed.groupContext); !errors.Is(err, errBadSignature) {
		t.Fatalf("another member's key: got %v, want the ValSem010 sentinel", err)
	}
}

// TestVerifyRefusesEveryFlippedBitOfTheSignature sweeps the signature bit by bit, derived over
// its own length rather than sampled.
//
// The sampling is the property. A verifier that compared the first byte of a 64 byte signature
// and nothing else passes a test that flips bit zero, and this project has already shipped a
// tag verifier of exactly that shape past a test of exactly that shape. Every bit of every byte
// is a forgery that must be refused, and the count is asserted so a sweep that stopped sweeping
// is loud rather than green.
func TestVerifyRefusesEveryFlippedBitOfTheSignature(t *testing.T) {
	signed := framingSignedMemberMessage(t)
	refused := 0
	for at := range signed.authContent.Auth.Signature {
		for bit := 0; bit < 8; bit++ {
			forged := *signed.authContent
			forged.Auth.Signature = bytes.Clone(signed.authContent.Auth.Signature)
			forged.Auth.Signature[at] ^= 1 << bit
			err := VerifyAuthenticatedContent(signed.crypto, signed.pub, &forged, signed.groupContext)
			if !errors.Is(err, errBadSignature) {
				t.Errorf("bit %d of byte %d flipped: got %v, want the ValSem010 sentinel", bit, at, err)
				continue
			}
			refused++
		}
	}
	if want := 8 * len(signed.authContent.Auth.Signature); refused != want {
		t.Fatalf("%d of %d single bit forgeries were refused", refused, want)
	}
	if refused == 0 {
		t.Fatal("the signature is empty, so this sweep flipped nothing")
	}
}

// TestVerifyRefusesEverySignatureLengthButItsOwn sweeps the length, derived the same way.
//
// A length mismatch is a REFUSAL and never a panic and never a short comparison. The empty and
// nil cases are the zero value of a FramedContentAuthData -- the state a freshly allocated one
// is in -- and this project shipped a bypass whose whole shape was an all zero authenticator
// reaching a comparison that accepted it.
func TestVerifyRefusesEverySignatureLengthButItsOwn(t *testing.T) {
	signed := framingSignedMemberMessage(t)
	signature := signed.authContent.Auth.Signature
	lengths := []struct {
		what string
		sig  []byte
	}{
		{what: "nil", sig: nil},
		{what: "empty", sig: []byte{}},
		{what: "one byte longer", sig: append(bytes.Clone(signature), 0x00)},
		{what: "twice as long", sig: append(bytes.Clone(signature), signature...)},
	}
	for cut := 0; cut < len(signature); cut++ {
		lengths = append(lengths, struct {
			what string
			sig  []byte
		}{what: fmt.Sprintf("truncated to %d of %d", cut, len(signature)), sig: bytes.Clone(signature[:cut])})
	}
	for _, one := range lengths {
		forged := *signed.authContent
		forged.Auth.Signature = one.sig
		if err := VerifyAuthenticatedContent(signed.crypto, signed.pub, &forged, signed.groupContext); !errors.Is(err, errBadSignature) {
			t.Errorf("%s: got %v, want the ValSem010 sentinel", one.what, err)
		}
	}
	if len(lengths) != 4+len(signature) {
		t.Fatalf("the sweep built %d lengths for a %d byte signature", len(lengths), len(signature))
	}
}

// framingAcceptingProvider is a provider whose VerifyWithLabel accepts everything.
//
// It exists to ask one question no real provider can be asked: does the framing layer's own
// refusal of the zero authenticator depend on the crypto agreeing? The three bypasses this
// project has shipped were all a caller trusting a layer underneath it, and the answer here has
// to be no.
type framingAcceptingProvider struct {
	CryptoProvider
}

func (self *framingAcceptingProvider) VerifyWithLabel(pub SignaturePublicKey, label string,
	content []byte, sig []byte) error {
	return nil
}

// TestVerifyRefusesTheZeroAuthenticatorWhateverTheProviderSays holds the empty signature check
// to being the framing layer's own.
//
// The control matters as much as the assertion and runs first: over the same accepting provider
// a signature of the right LENGTH and entirely wrong content is accepted, which is what says the
// provider really is lenient. Without it a refusal here would be indistinguishable from a real
// provider doing the work.
func TestVerifyRefusesTheZeroAuthenticatorWhateverTheProviderSays(t *testing.T) {
	signed := framingSignedMemberMessage(t)
	lenient := &framingAcceptingProvider{CryptoProvider: signed.crypto}

	forged := *signed.authContent
	forged.Auth.Signature = bytes.Repeat([]byte{0xaa}, len(signed.authContent.Auth.Signature))
	if err := VerifyAuthenticatedContent(lenient, signed.pub, &forged, signed.groupContext); err != nil {
		t.Fatalf("the accepting provider refused a forged signature (%v), so it is not lenient and the assertion below states nothing", err)
	}

	for _, one := range []struct {
		what string
		sig  []byte
	}{{what: "nil", sig: nil}, {what: "empty", sig: []byte{}}} {
		zero := *signed.authContent
		zero.Auth.Signature = one.sig
		if err := VerifyAuthenticatedContent(lenient, signed.pub, &zero, signed.groupContext); !errors.Is(err, errBadSignature) {
			t.Errorf("%s signature over a provider that accepts everything: got %v, want the ValSem010 sentinel",
				one.what, err)
		}
	}
}

// ---------------------------------------------------------------------------
// every field of the preimage
// ---------------------------------------------------------------------------

// framingPreimageInput is the three arguments a FramedContentTBS is built out of.
type framingPreimageInput struct {
	wireFormat   WireFormat
	content      *FramedContent
	groupContext []byte
}

// framingFieldMoves is one move per FIELD of the preimage, keyed by the struct and field the
// move is about.
//
// Every entry answers a base and a moved input that differ in that field alone, except where
// the wire format makes that impossible and the entry says so. This is the table the sweep
// below joins against the two structures by reflection, in both directions, so a field added to
// either one has no entry and fails rather than being left out of the sweep.
//
// This is the shape p5 task 6 found for LeafNodeTBS: omit group_id or leaf_index and everything
// still round trips, while a leaf lifted out of another group verifies. The equivalent here is
// worse, because a field dropped from this preimage is a message another member can replay.
var framingFieldMoves = map[string]func(t *testing.T) (framingPreimageInput, framingPreimageInput){
	"framedContentTBS.WireFormat": func(t *testing.T) (framingPreimageInput, framingPreimageInput) {
		return framingPreimageInput{WireFormatPrivateMessage, framingTestMemberContent(), framingTestGroupContext(t)},
			framingPreimageInput{WireFormatPublicMessage, framingTestMemberContent(), framingTestGroupContext(t)}
	},
	// the whole content, moved as one. Its own fields are moved one at a time below; this
	// entry is what says the field EXISTS in the preimage at all, which is the reading that
	// survives a codec that stopped writing any of it.
	"framedContentTBS.Content": func(t *testing.T) (framingPreimageInput, framingPreimageInput) {
		moved := framingTestMemberContent()
		moved.ApplicationData = []byte("a different payload entirely")
		return framingPreimageInput{WireFormatPrivateMessage, framingTestMemberContent(), framingTestGroupContext(t)},
			framingPreimageInput{WireFormatPrivateMessage, moved, framingTestGroupContext(t)}
	},
	// the epoch binding. A preimage that dropped it is a signature valid in every epoch of the
	// group, which is the single most expensive omission available here.
	"framedContentTBS.GroupContext": func(t *testing.T) (framingPreimageInput, framingPreimageInput) {
		moved := bytes.Clone(framingTestGroupContext(t))
		moved[len(moved)-1] ^= 0xff
		return framingPreimageInput{WireFormatPrivateMessage, framingTestMemberContent(), framingTestGroupContext(t)},
			framingPreimageInput{WireFormatPrivateMessage, framingTestMemberContent(), moved}
	},
	"FramedContent.GroupId": func(t *testing.T) (framingPreimageInput, framingPreimageInput) {
		moved := framingTestMemberContent()
		moved.GroupId = []byte{0x01, 0x03}
		return framingPreimageInput{WireFormatPrivateMessage, framingTestMemberContent(), framingTestGroupContext(t)},
			framingPreimageInput{WireFormatPrivateMessage, moved, framingTestGroupContext(t)}
	},
	"FramedContent.Epoch": func(t *testing.T) (framingPreimageInput, framingPreimageInput) {
		moved := framingTestMemberContent()
		moved.Epoch++
		return framingPreimageInput{WireFormatPrivateMessage, framingTestMemberContent(), framingTestGroupContext(t)},
			framingPreimageInput{WireFormatPrivateMessage, moved, framingTestGroupContext(t)}
	},
	// the sender, which for a member is the leaf index -- the field that says WHO signed. A
	// preimage that dropped it is one member's signature accepted as another's.
	"FramedContent.Sender": func(t *testing.T) (framingPreimageInput, framingPreimageInput) {
		moved := framingTestMemberContent()
		moved.Sender = Sender{SenderType: SenderTypeMember, LeafIndex: 9}
		return framingPreimageInput{WireFormatPrivateMessage, framingTestMemberContent(), framingTestGroupContext(t)},
			framingPreimageInput{WireFormatPrivateMessage, moved, framingTestGroupContext(t)}
	},
	"FramedContent.AuthenticatedData": func(t *testing.T) (framingPreimageInput, framingPreimageInput) {
		moved := framingTestMemberContent()
		moved.AuthenticatedData = []byte{0x0a}
		return framingPreimageInput{WireFormatPrivateMessage, framingTestMemberContent(), framingTestGroupContext(t)},
			framingPreimageInput{WireFormatPrivateMessage, moved, framingTestGroupContext(t)}
	},
	// the content type, moved together with the arm it selects, because on the wire the two are
	// one thing: an application message with a proposal beside it does not encode at all. What
	// this row states is therefore that the discriminant and its arm are both in the preimage,
	// and the two rows below separate the arms from each other.
	"FramedContent.ContentType": func(t *testing.T) (framingPreimageInput, framingPreimageInput) {
		return framingPreimageInput{WireFormatPublicMessage, framingTestMemberContent(), framingTestGroupContext(t)},
			framingPreimageInput{WireFormatPublicMessage, framingTestProposalContent(), framingTestGroupContext(t)}
	},
	"FramedContent.ApplicationData": func(t *testing.T) (framingPreimageInput, framingPreimageInput) {
		moved := framingTestMemberContent()
		moved.ApplicationData = []byte("payloae")
		return framingPreimageInput{WireFormatPrivateMessage, framingTestMemberContent(), framingTestGroupContext(t)},
			framingPreimageInput{WireFormatPrivateMessage, moved, framingTestGroupContext(t)}
	},
	// the proposal arm, moved inside itself: two removals of two different leaves. A preimage
	// that carried the discriminant and dropped the body is a signature over "some proposal",
	// which every member of the group could replay as a removal of anybody.
	"FramedContent.Proposal": func(t *testing.T) (framingPreimageInput, framingPreimageInput) {
		moved := framingTestProposalContent()
		moved.Proposal = &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 4}}
		return framingPreimageInput{WireFormatPublicMessage, framingTestProposalContent(), framingTestGroupContext(t)},
			framingPreimageInput{WireFormatPublicMessage, moved, framingTestGroupContext(t)}
	},
	// the commit arm, moved the same way: an empty commit against one naming a proposal.
	"FramedContent.Commit": func(t *testing.T) (framingPreimageInput, framingPreimageInput) {
		moved := framingTestCommitContent()
		moved.Commit = &Commit{Proposals: []ProposalOrRef{{
			Type:      ProposalOrRefTypeReference,
			Reference: ProposalRef(bytes.Repeat([]byte{0x77}, 32)),
		}}}
		return framingPreimageInput{WireFormatPublicMessage, framingTestCommitContent(), framingTestGroupContext(t)},
			framingPreimageInput{WireFormatPublicMessage, moved, framingTestGroupContext(t)}
	},
	// the sender's own three fields. FramedContent.Sender above moves the whole value and
	// moves the leaf index inside it, which is one field of three: these three are what the
	// walk reaches now that it descends into a structure held by value, and each of them
	// decides WHO a message is attributed to.
	//
	// The sender type is moved between the two arms that bind the group context, so the row
	// separates the discriminant rather than the binding rule -- which is
	// TestEverySenderTypeBindsTheGroupContextSection61GivesIt's subject and not this sweep's.
	// A preimage that dropped it is a member's commit accepted as an external joiner's.
	"Sender.SenderType": func(t *testing.T) (framingPreimageInput, framingPreimageInput) {
		joining := framingTestCommitContent()
		joining.Sender = Sender{SenderType: SenderTypeNewMemberCommit}
		return framingPreimageInput{WireFormatPublicMessage, framingTestCommitContent(), framingTestGroupContext(t)},
			framingPreimageInput{WireFormatPublicMessage, joining, framingTestGroupContext(t)}
	},
	"Sender.LeafIndex": func(t *testing.T) (framingPreimageInput, framingPreimageInput) {
		moved := framingTestMemberContent()
		moved.Sender = Sender{SenderType: SenderTypeMember, LeafIndex: 5}
		return framingPreimageInput{WireFormatPrivateMessage, framingTestMemberContent(), framingTestGroupContext(t)},
			framingPreimageInput{WireFormatPrivateMessage, moved, framingTestGroupContext(t)}
	},
	// the external sender's index, which is the arm of Sender the leaf index is not. It binds
	// no group context, so both inputs of this row carry none -- and a preimage that dropped
	// it is one external sender's proposal accepted as any other's.
	"Sender.SenderIndex": func(t *testing.T) (framingPreimageInput, framingPreimageInput) {
		base := framingTestProposalContent()
		base.Sender = Sender{SenderType: SenderTypeExternal, SenderIndex: 0}
		moved := framingTestProposalContent()
		moved.Sender = Sender{SenderType: SenderTypeExternal, SenderIndex: 5}
		return framingPreimageInput{WireFormatPublicMessage, base, nil},
			framingPreimageInput{WireFormatPublicMessage, moved, nil}
	},
}

// framingPreimageStructTypes is every structure the preimage is assembled from, WALKED out of
// framedContentTBS rather than listed beside it.
//
// The walk descends through a field held by VALUE and stops at a pointer, and that rule is the
// whole of the class. A structure held by value is present in every preimage this type can
// produce, so its fields are as much of what gets signed as its parent's are; a pointer to one
// is an ARM the content type selects, is absent from most preimages, and is moved as a whole
// by the row that names it -- FramedContent.Proposal and FramedContent.Commit are exactly
// those two.
//
// Listed, this was framedContentTBS and FramedContent and stopped there, which is one level
// shallower than this sweep's own prose ("every field of the preimage"). Sender's three fields
// sat under a single FramedContent.Sender row that moves the leaf index alone, so a field
// added to Sender entered no sweep and failed nothing.
func framingPreimageStructTypes(t *testing.T) []reflect.Type {
	t.Helper()
	found := []reflect.Type{}
	queue := []reflect.Type{reflect.TypeOf(framedContentTBS{})}
	for len(queue) != 0 {
		declared := queue[0]
		queue = queue[1:]
		if slices.Contains(found, declared) {
			continue
		}
		if declared.Name() == "" {
			t.Fatal("the walk reached an unnamed struct type, which no row of this sweep can be keyed by")
		}
		if declared.NumField() == 0 {
			t.Fatalf("%s declares no fields, so the sweep below runs over less than the preimage",
				declared.Name())
		}
		found = append(found, declared)
		for i := range declared.NumField() {
			if field := declared.Field(i).Type; field.Kind() == reflect.Struct {
				queue = append(queue, field)
			}
		}
	}
	if len(found) < 2 {
		t.Fatalf("the walk reached %d structure, so it descended into nothing and this sweep is one type wide", len(found))
	}
	return found
}

// framingPreimageFieldNames is every field of every one of those structures, read off the types
// rather than written down.
func framingPreimageFieldNames(t *testing.T) []string {
	t.Helper()
	names := []string{}
	for _, declared := range framingPreimageStructTypes(t) {
		for i := range declared.NumField() {
			names = append(names, declared.Name()+"."+declared.Field(i).Name)
		}
	}
	slices.Sort(names)
	return names
}

// TestASignatureOverOneTbsNeverVerifiesAgainstAnother is the omitted-field gate, run over every
// field of the preimage rather than over the ones somebody thought of.
//
// Two things are asserted per field and they are different claims. The BYTES must differ, which
// says the field reaches the preimage at all; and the signature over one must be refused
// against the other, which says the verifier rebuilds the preimage from the same fields the
// signer used. A codec that wrote a field the verifier then ignored would satisfy the first and
// not the second.
func TestASignatureOverOneTbsNeverVerifiesAgainstAnother(t *testing.T) {
	declared := framingPreimageFieldNames(t)
	written := slices.Sorted(maps.Keys(framingFieldMoves))
	if !slices.Equal(declared, written) {
		t.Fatalf("the preimage is assembled out of the fields %v and this sweep moves %v; a field with no move is a field nothing here judges",
			declared, written)
	}
	crypto := newTestCrypto(t)
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	for _, name := range written {
		base, moved := framingFieldMoves[name](t)
		baseTbs, err := FramedContentTBSBytes(base.wireFormat, base.content, base.groupContext)
		if err != nil {
			t.Errorf("%s: base preimage: %v", name, err)
			continue
		}
		movedTbs, err := FramedContentTBSBytes(moved.wireFormat, moved.content, moved.groupContext)
		if err != nil {
			t.Errorf("%s: moved preimage: %v", name, err)
			continue
		}
		if bytes.Equal(baseTbs, movedTbs) {
			t.Errorf("%s: moving it leaves the preimage byte identical, so the field is not in what gets signed",
				name)
			continue
		}
		signed, err := SignAuthenticatedContent(crypto, priv, base.wireFormat, base.content, base.groupContext)
		if err != nil {
			t.Errorf("%s: sign: %v", name, err)
			continue
		}
		// a commit is refused at ValSem009 before its signature is in question, so the rows
		// whose content is a commit carry a tag. What this sweep is about is the preimage, and
		// a refusal for a missing tag would hide whatever answer the signature gave.
		if base.content.ContentType == ContentTypeCommit {
			signed.Auth.ConfirmationTag = bytes.Repeat([]byte{0x5a}, crypto.HashSize())
		}
		if err := VerifyAuthenticatedContent(crypto, pub, signed, base.groupContext); err != nil {
			t.Errorf("%s: the signature does not verify against its own preimage: %v", name, err)
			continue
		}
		lifted := &AuthenticatedContent{
			WireFormat: moved.wireFormat,
			Content:    *moved.content,
			Auth:       FramedContentAuthData{Signature: signed.Auth.Signature},
		}
		if moved.content.ContentType == ContentTypeCommit {
			lifted.Auth.ConfirmationTag = bytes.Repeat([]byte{0x5a}, crypto.HashSize())
		}
		if err := VerifyAuthenticatedContent(crypto, pub, lifted, moved.groupContext); !errors.Is(err, errBadSignature) {
			t.Errorf("%s: a signature over one preimage verified against another: got %v, want the ValSem010 sentinel",
				name, err)
		}
	}
}

// TestASignatureUnderOneWireFormatDoesNotVerifyUnderAnother is the wire format binding, over
// every ORDERED PAIR of the registry rather than over the one pair this plan names.
//
// The wire format is in the preimage precisely so that a PublicMessage cannot be replayed as a
// PrivateMessage or the reverse, which is the pair the plan names -- and the registry has five
// members, so a preimage that separated those two and confused any other pair would pass a test
// written for the pair alone. The class is derived off the registry for that reason.
func TestASignatureUnderOneWireFormatDoesNotVerifyUnderAnother(t *testing.T) {
	crypto := newTestCrypto(t)
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	groupContext := framingTestGroupContext(t)
	derived := registryConstantsOfType(t, "WireFormat")
	if len(derived) < 2 {
		t.Fatalf("the WireFormat registry derived %d constants, so there is no pair to confuse", len(derived))
	}
	names := slices.Sorted(maps.Keys(derived))
	compared := 0
	for _, signedUnder := range names {
		signed, err := SignAuthenticatedContent(crypto, priv, WireFormat(derived[signedUnder]),
			framingTestMemberContent(), groupContext)
		if err != nil {
			t.Errorf("sign under %s: %v", signedUnder, err)
			continue
		}
		for _, verifiedUnder := range names {
			replayed := *signed
			replayed.WireFormat = WireFormat(derived[verifiedUnder])
			err := VerifyAuthenticatedContent(crypto, pub, &replayed, groupContext)
			if signedUnder == verifiedUnder {
				if err != nil {
					t.Errorf("%s: a message verified under the wire format it was signed under was refused: %v",
						signedUnder, err)
				}
				continue
			}
			compared++
			if !errors.Is(err, errBadSignature) {
				t.Errorf("a message signed under %s verified under %s: got %v, want the ValSem010 sentinel",
					signedUnder, verifiedUnder, err)
			}
		}
	}
	if want := len(names) * (len(names) - 1); compared != want {
		t.Fatalf("%d of the %d ordered wire format pairs were compared", compared, want)
	}
}

// TestVerifyRefusesACommitWithNoConfirmationTag is ValSem009, with the positive case beside it
// so the rule is not satisfied by a verifier that refuses every commit.
//
// The order matters and is asserted: the tag is checked AFTER the signature, so a commit whose
// signature is wrong AND whose tag is missing is refused as ValSem010. An unauthenticated
// message must not learn which of the two rules it failed.
func TestVerifyRefusesACommitWithNoConfirmationTag(t *testing.T) {
	crypto := newTestCrypto(t)
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	groupContext := framingTestGroupContext(t)
	signed, err := SignAuthenticatedContent(crypto, priv, WireFormatPublicMessage,
		framingTestCommitContent(), groupContext)
	if err != nil {
		t.Fatalf("sign a commit: %v", err)
	}
	// every spelling of an absent tag and not the nil one a fresh signature happens to
	// carry. ValSem009 written on the pointer accepts a commit whose tag is an empty non
	// nil slice, which is a commit binding itself to no transcript at all.
	for _, empty := range emptyByteSpellings() {
		untagged := *signed
		untagged.Auth.ConfirmationTag = empty.value
		if err := VerifyAuthenticatedContent(crypto, pub, &untagged, groupContext); !errors.Is(err, errMissingConfirmationTag) {
			t.Fatalf("a commit whose confirmation tag is %s: got %v, want the ValSem009 sentinel", empty.what, err)
		}
	}
	tagged := *signed
	tagged.Auth.ConfirmationTag = bytes.Repeat([]byte{0x5a}, crypto.HashSize())
	if err := VerifyAuthenticatedContent(crypto, pub, &tagged, groupContext); err != nil {
		t.Fatalf("a commit carrying a confirmation tag was refused: %v", err)
	}
	// the ordering: a bad signature under a missing tag answers ValSem010 and not ValSem009
	forged := *signed
	forged.Auth.Signature = bytes.Clone(signed.Auth.Signature)
	forged.Auth.Signature[0] ^= 0x01
	if err := VerifyAuthenticatedContent(crypto, pub, &forged, groupContext); !errors.Is(err, errBadSignature) {
		t.Fatalf("a forged commit with no tag: got %v, want the ValSem010 sentinel", err)
	}
	// and a proposal is not held to carrying one, which is what stops the rule being "refuse
	// everything that has no tag"
	proposal, err := SignAuthenticatedContent(crypto, priv, WireFormatPublicMessage,
		framingTestProposalContent(), groupContext)
	if err != nil {
		t.Fatalf("sign a proposal: %v", err)
	}
	if err := VerifyAuthenticatedContent(crypto, pub, proposal, groupContext); err != nil {
		t.Fatalf("a proposal carrying no confirmation tag was refused: %v", err)
	}
}

// ---------------------------------------------------------------------------
// the published corpus
// ---------------------------------------------------------------------------

// One signature per registered suite per published public message: mlswg's message-protection
// corpus carries a proposal and a commit for each.
//
// Counted rather than assumed, for the reason every known answer count in this package is: a
// filter that stopped matching turns a corpus comparison into a loop that runs zero times and
// reports PASS, which is the one outcome a known answer test must not be able to reach.
const framedContentSignatureComparisons = 4

// framingPublishedPublicMessage decodes one MLSMessage carrying a PublicMessage out of the
// corpus, through THIS package's own codecs.
//
// Decoded rather than spliced, which is the difference between this and the membership tag's
// own reader next door: p4 owns no framing types and had to locate the boundary by searching
// for the published body, and this plan owns them. What is read is version, wire format, the
// FramedContent, the FramedContentAuthData under that content's own type, and the membership
// tag a member's public message ends with -- and the reader is required to be empty at the end,
// so a decode that stopped early cannot pass for one that read the whole message.
func framingPublishedPublicMessage(t *testing.T, at string, mlsMessage []byte) *AuthenticatedContent {
	t.Helper()
	r := syntax.NewReader(mlsMessage)
	version, err := r.ReadUint16()
	if err != nil {
		t.Fatalf("%s: read the protocol version: %v", at, err)
	}
	if ProtocolVersion(version) != ProtocolVersionMls10 {
		t.Fatalf("%s: the message names protocol version %#04x, want mls10", at, version)
	}
	wireFormat, err := r.ReadUint16()
	if err != nil {
		t.Fatalf("%s: read the wire format: %v", at, err)
	}
	if WireFormat(wireFormat) != WireFormatPublicMessage {
		t.Fatalf("%s: the message names wire format %#04x, want a public message", at, wireFormat)
	}
	authContent := &AuthenticatedContent{WireFormat: WireFormat(wireFormat)}
	if err := authContent.Content.UnmarshalMLS(r); err != nil {
		t.Fatalf("%s: decode the framed content: %v", at, err)
	}
	if err := authContent.Auth.UnmarshalMLS(r, authContent.Content.ContentType); err != nil {
		t.Fatalf("%s: decode the auth data: %v", at, err)
	}
	if authContent.Content.Sender.SenderType != SenderTypeMember {
		t.Fatalf("%s: the published message is from sender type %d, and this reader expects the member arm that carries a membership tag",
			at, authContent.Content.Sender.SenderType)
	}
	if _, err := r.ReadOpaque(); err != nil {
		t.Fatalf("%s: read the membership tag: %v", at, err)
	}
	if err := r.Done(); err != nil {
		t.Fatalf("%s: %v, so this reader did not consume the whole published message and the content it answers is not all of it",
			at, err)
	}
	return authContent
}

// TestTheFramedContentSignatureIsTheOneMlswgPublished is the known answer test for this whole
// file, against signatures this package did not compute.
//
// Everything else here is self consistent by construction: sign, verify, and every refusal is
// this package agreeing with itself. A preimage that inlined the group context with a length
// prefix, or that omitted the wire format, or that ordered the fields differently, signs and
// verifies against itself perfectly and fails only against another implementation. This is that
// other implementation.
//
// The corpus is authenticated against upstream's git object store before a byte of it is read,
// through the same loader p4's tag known answer tests use: a known answer test that compares
// against a file an edit can change is a known answer test that can be made to agree with
// anything.
//
// The group context is rebuilt out of the entry's own four fields and encoded by this package's
// codec, which the group context task already holds to this same corpus family. Nothing here is
// circular -- a wrong reconstruction makes the comparison FAIL rather than pass, since only the
// right preimage under the right key verifies a signature somebody else made.
func TestTheFramedContentSignatureIsTheOneMlswgPublished(t *testing.T) {
	entries := []messageProtectionKatEntry{}
	mustLoadAuthenticatedCorpus(t, messageProtectionKatFile, &entries)
	if len(entries) == 0 {
		t.Fatalf("%s parsed to no entries, so every comparison below would run over nothing", messageProtectionKatFile)
	}
	compared := 0
	matched := []CipherSuite{}
	for _, entry := range entries {
		suite := CipherSuite(entry.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		matched = append(matched, suite)
		crypto := mustProvider(t, suite)
		suiteAt := fmt.Sprintf("%s suite %#04x", messageProtectionKatFile, uint16(suite))
		signaturePub := SignaturePublicKey(mustDecodeHex(t, suiteAt+" signature_pub", entry.SignaturePub))
		groupContext, err := syntax.Marshal(&GroupContext{
			Version:                 ProtocolVersionMls10,
			CipherSuite:             suite,
			GroupId:                 mustDecodeHex(t, suiteAt+" group_id", entry.GroupId),
			Epoch:                   entry.Epoch,
			TreeHash:                mustDecodeHex(t, suiteAt+" tree_hash", entry.TreeHash),
			ConfirmedTranscriptHash: mustDecodeHex(t, suiteAt+" confirmed_transcript_hash", entry.ConfirmedTranscriptHash),
		})
		if err != nil {
			t.Fatalf("%s: encode the group context these messages were framed under: %v", suiteAt, err)
		}
		for _, message := range []struct {
			what string
			pub  string
		}{
			{what: "proposal_pub", pub: entry.ProposalPub},
			{what: "commit_pub", pub: entry.CommitPub},
		} {
			at := suiteAt + " " + message.what
			authContent := framingPublishedPublicMessage(t, at, mustDecodeHex(t, at, message.pub))
			if err := VerifyAuthenticatedContent(crypto, signaturePub, authContent, groupContext); err != nil {
				t.Errorf("%s: %v. The signature is over version || wire_format || FramedContent || GroupContext with the context inlined and no length prefix, and nothing else; a preimage that agrees with itself agrees with no other implementation",
					at, err)
				continue
			}
			// and the same message under the epoch next door is refused, so what passed above
			// is the binding rather than a verifier that accepts whatever it is handed
			otherEpoch, err := syntax.Marshal(&GroupContext{
				Version:                 ProtocolVersionMls10,
				CipherSuite:             suite,
				GroupId:                 mustDecodeHex(t, suiteAt+" group_id", entry.GroupId),
				Epoch:                   entry.Epoch + 1,
				TreeHash:                mustDecodeHex(t, suiteAt+" tree_hash", entry.TreeHash),
				ConfirmedTranscriptHash: mustDecodeHex(t, suiteAt+" confirmed_transcript_hash", entry.ConfirmedTranscriptHash),
			})
			if err != nil {
				t.Fatalf("%s: encode the neighbouring epoch's group context: %v", at, err)
			}
			if err := VerifyAuthenticatedContent(crypto, signaturePub, authContent, otherEpoch); !errors.Is(err, errBadSignature) {
				t.Errorf("%s: the published signature verified under the next epoch's group context: got %v, want the ValSem010 sentinel",
					at, err)
			}
			compared++
		}
	}
	if compared != framedContentSignatureComparisons {
		t.Fatalf("%d published framed content signatures were verified, want %d; the loop matched %v",
			compared, framedContentSignatureComparisons, matched)
	}
	if got := slices.Sorted(slices.Values(matched)); !slices.Equal(got, Suites()) {
		t.Fatalf("%s answered for %v and this package registers %v", messageProtectionKatFile, got, Suites())
	}
}

// TestTheFramedContentTbsLabelIsTheOneSection61Names holds the domain separation this signature
// rests on.
//
// A label spelled one way in both halves of this package agrees with itself, so nothing
// behavioural in here can see it. What separates them is a signature made under a NEIGHBOURING
// label over the same preimage, which must not verify: that is the whole of what stops a leaf
// node signature, an update path node signature and a framed content signature being
// interchangeable under one key.
func TestTheFramedContentTbsLabelIsTheOneSection61Names(t *testing.T) {
	if framedContentTBSLabel != "FramedContentTBS" {
		t.Fatalf("the framing signature label is %q, and RFC 9420 section 6.1 writes FramedContentTBS",
			framedContentTBSLabel)
	}
	crypto := newTestCrypto(t)
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	groupContext := framingTestGroupContext(t)
	content := framingTestMemberContent()
	tbs, err := FramedContentTBSBytes(WireFormatPrivateMessage, content, groupContext)
	if err != nil {
		t.Fatalf("tbs: %v", err)
	}
	for _, label := range []string{leafNodeSignatureLabel, updatePathNodeLabel, "FramedContentTbs", ""} {
		if label == framedContentTBSLabel {
			t.Fatalf("%q is the framing label itself, so this row compares it against itself", label)
		}
		signature, err := crypto.SignWithLabel(priv, label, tbs)
		if err != nil {
			t.Fatalf("sign under %q: %v", label, err)
		}
		lifted := &AuthenticatedContent{
			WireFormat: WireFormatPrivateMessage,
			Content:    *content,
			Auth:       FramedContentAuthData{Signature: signature},
		}
		if err := VerifyAuthenticatedContent(crypto, pub, lifted, groupContext); !errors.Is(err, errBadSignature) {
			t.Errorf("a signature over this preimage under the label %q verified as a framed content signature: got %v, want the ValSem010 sentinel",
				label, err)
		}
	}
	// and the label really is what the signer used, read back through the provider rather than
	// through this package's own verify
	signed, err := SignAuthenticatedContent(crypto, priv, WireFormatPrivateMessage, content, groupContext)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := crypto.VerifyWithLabel(pub, framedContentTBSLabel, tbs, signed.Auth.Signature); err != nil {
		t.Errorf("the signature this package made is not a signature over the FramedContentTBS preimage under the section 6.1 label: %v", err)
	}
}

// TestTheFramingRefusalsAnswerTheirOwnSentinels keeps the two ValSem codes distinguishable from
// each other and from the structural refusals of the same layer.
//
// A caller branching on ValSem010 must not be answered yes by ValSem009 or by a codec's arm
// mismatch, and this is where that is stated rather than in each test's own assertion: every
// assertion in this file reads errors.Is against one of the two, so two values that answered for
// each other would satisfy all of them at once.
func TestTheFramingRefusalsAnswerTheirOwnSentinels(t *testing.T) {
	for _, one := range []struct {
		name  string
		value error
		other []error
	}{
		{name: "errFramedContentBadSignature", value: errFramedContentBadSignature,
			other: []error{errMissingConfirmationTag, ErrContentArmMismatch, ErrMissingGroupContext,
				ErrUnexpectedGroupContext, ErrUnknownSenderType, ErrUnknownWireFormat, errNilFramedContent,
				errNilAuthenticatedContent}},
		{name: "errMissingConfirmationTag", value: errMissingConfirmationTag,
			other: []error{errFramedContentBadSignature, errBadSignature, ErrCryptoBadSignature}},
		// ValSem007 and ValSem008. Each names the other, because "the sender sent no tag" and
		// "the tag does not verify" are the pair a validator has to keep apart, and each names
		// the signature refusal next door, because a caller branching on ValSem010 must not be
		// answered yes by a membership tag that failed.
		{name: "errMissingMembershipTag", value: errMissingMembershipTag,
			other: []error{errBadMembershipTag, errFramedContentBadSignature, errBadSignature,
				errMissingConfirmationTag, ErrCryptoBadSignature, ErrSenderNotMember}},
		{name: "errBadMembershipTag", value: errBadMembershipTag,
			other: []error{errMissingMembershipTag, errFramedContentBadSignature, errBadSignature,
				errMissingConfirmationTag, ErrCryptoBadSignature, ErrSenderNotMember}},
		// ValSem005. It names both tag refusals and the signature's, because a validator that
		// could not tell "this was framed in the clear" from "this was not authenticated" would
		// report the wrong rule for the wrong message -- and it names the structural pair next
		// door, because an application message in a public frame is neither an arm mismatch nor
		// an unregistered content type.
		{name: "errApplicationMustBeCiphertext", value: errApplicationMustBeCiphertext,
			other: []error{errMissingMembershipTag, errBadMembershipTag, errFramedContentBadSignature,
				errBadSignature, errMissingConfirmationTag, ErrCryptoBadSignature,
				ErrContentArmMismatch, ErrUnknownContentType, ErrWireFormatMismatch}},
		// the two argument refusals section 6.2's open adds. Each names the other and both name
		// the framing layer's existing pair: "the caller passed nothing" and "no key exists for
		// this sender" are different things to do about, and neither is a message that failed.
		{name: "errNilPublicMessage", value: errNilPublicMessage,
			other: []error{errNilAuthenticatedContent, errNilFramedContent, errNilSignatureKeyResolver,
				errApplicationMustBeCiphertext, errFramedContentBadSignature}},
		{name: "errNilSignatureKeyResolver", value: errNilSignatureKeyResolver,
			other: []error{errNilAuthenticatedContent, errNilFramedContent, errNilPublicMessage,
				errApplicationMustBeCiphertext, errFramedContentBadSignature}},
		// section 6.2's select on the tag, in the direction that has no field on the wire. It
		// names both tag refusals, because "this message carries a tag nothing can check" and
		// "this message is missing the one thing that says it came from inside the group" are
		// opposite mistakes and a caller told the wrong one is sent to fix the wrong field, and
		// it names the structural pair next door for ErrUnexpectedGroupContext's reason: the two
		// are the same rule about two different fields and a caller branching on one must not be
		// answered yes by the other.
		{name: "errUnexpectedMembershipTag", value: errUnexpectedMembershipTag,
			other: []error{errMissingMembershipTag, errBadMembershipTag, errFramedContentBadSignature,
				errApplicationMustBeCiphertext, ErrUnexpectedGroupContext, ErrMissingGroupContext,
				ErrSenderNotMember, ErrUnknownSenderType}},
	} {
		if one.value == nil || one.value.Error() == "" {
			t.Fatalf("%s is nil or has an empty message", one.name)
		}
		if !strings.HasPrefix(one.value.Error(), "mls: ") {
			t.Errorf("%s reads %q; every typed error of this package names the package it came from",
				one.name, one.value.Error())
		}
		for _, other := range one.other {
			if errors.Is(one.value, other) {
				t.Errorf("%s answers to %v, so a caller branching on the two reads one as the other",
					one.name, other)
			}
		}
	}
	// the one wrap this layer does argue for, in the direction it argues for it: the framing
	// refusal answers the broad "the signature did not verify" question, so a caller that only
	// wants that keeps being answered by it.
	if !errors.Is(errFramedContentBadSignature, errBadSignature) {
		t.Error("the framing signature refusal does not answer the package's ValSem010 stand in, so a caller matching that name stops matching this layer")
	}
}

// framingUnregisteredCodePoint is the smallest code point of a registry's width that the
// registry does not hold.
//
// Derived rather than written down, so a later task that registers 0x0006 as a wire format does
// not leave a row below building "the unknown one" over a code point that has since become
// known. That row would go on passing while asserting the opposite of what it says.
func framingUnregisteredCodePoint(t *testing.T, typeName string, width uint64) uint64 {
	t.Helper()
	registered := registryConstantsOfType(t, typeName)
	for candidate := uint64(1); candidate <= width; candidate++ {
		taken := false
		for _, value := range registered {
			if value == candidate {
				taken = true
				break
			}
		}
		if !taken {
			return candidate
		}
	}
	t.Fatalf("every code point of %s up to %d is registered, so this gate has no unknown one to build",
		typeName, width)
	return 0
}

// framingStructuralPreimageRefusals is every input this package can assemble that NO preimage can
// be built out of, keyed by what makes it one.
//
// Derived over the sender type registry plus a code point neither registry holds, rather than
// sampled: which group context arm a sender type forbids comes off senderBindsGroupContext rather
// than off a list here, so a sender type or a wire format a later task registers joins every sweep
// reading this by existing.
//
// Two gates read it and they ask opposite questions of the same rows. One asserts that a message
// carrying a signature is answered by the preimage's own refusal verbatim; the other asserts that
// the same message carrying NO membership tag is answered by ValSem007 instead, which is the only
// input that separates the two orders verifyMembershipTag's first two guards can be written in.
func framingStructuralPreimageRefusals(t *testing.T) map[string]framingPreimageInput {
	t.Helper()
	structural := map[string]framingPreimageInput{}
	for name, code := range registryConstantsOfType(t, "SenderType") {
		senderType := SenderType(code)
		binds, err := senderBindsGroupContext(senderType)
		if err != nil {
			t.Errorf("%s is a registered sender type and senderBindsGroupContext refused it: %v", name, err)
			continue
		}
		content := framingTestProposalContent()
		content.Sender = Sender{SenderType: senderType}
		// the arm this sender type forbids: one that binds the epoch handed no context, one
		// that binds none handed a context
		forbidden := framingTestGroupContext(t)
		if binds {
			forbidden = nil
		}
		structural[name+" handed the group context arm it forbids"] =
			framingPreimageInput{WireFormatPublicMessage, content, forbidden}
	}
	if len(structural) == 0 {
		t.Fatal("no registered sender type produced a row, so every gate reading this runs over the empty set")
	}
	unknownSender := framingTestProposalContent()
	unknownSender.Sender = Sender{SenderType: SenderType(framingUnregisteredCodePoint(t, "SenderType", 0xff))}
	structural["a sender type no registry holds"] =
		framingPreimageInput{WireFormatPublicMessage, unknownSender, framingTestGroupContext(t)}
	structural["a wire format no registry holds"] = framingPreimageInput{
		WireFormat(framingUnregisteredCodePoint(t, "WireFormat", 0xffff)),
		framingTestMemberContent(), framingTestGroupContext(t)}
	return structural
}

// TestVerifyAnswersThePreimagesRefusalVerbatimAndCollapsesEverySignatureFailure states which of
// the two rules each refusal of VerifyAuthenticatedContent falls under.
//
// The function's documentation used to say every failure collapses into
// errFramedContentBadSignature, and four sentinels travel out of it unchanged -- three of them
// reachable from a message a PEER sent, because the arm they select on is the sender type
// inside that message. Nothing observed the claim in either direction, so the prose and the
// code disagreed silently, and a later ValSem code mapper keyed on the sentinel would have had
// no code for those inputs.
//
// Both halves are derived. The structural half runs the group context arm each REGISTERED
// sender type forbids, plus a code point neither registry holds, and asserts the verifier hands
// back the preimage builder's own error -- compared by message, so a row cannot pass by
// answering some other value that happens to wrap the same sentinel. The signature half runs
// every way this package can produce a signature that does not verify and asserts each answers
// the ONE value by identity rather than by errors.Is, which is what "and nothing narrower"
// means.
func TestVerifyAnswersThePreimagesRefusalVerbatimAndCollapsesEverySignatureFailure(t *testing.T) {
	signed := framingSignedMemberMessage(t)
	signature := signed.authContent.Auth.Signature
	if len(signature) == 0 {
		t.Fatal("the fixture carries no signature, so every row below is refused before it is reached")
	}

	// the structural half: inputs no preimage can be assembled from at all
	structural := framingStructuralPreimageRefusals(t)

	for _, name := range slices.Sorted(maps.Keys(structural)) {
		one := structural[name]
		_, preimage := FramedContentTBSBytes(one.wireFormat, one.content, one.groupContext)
		if preimage == nil {
			t.Errorf("%s: the preimage was assembled, so this row states nothing about a refusal", name)
			continue
		}
		answered := VerifyAuthenticatedContent(signed.crypto, signed.pub, &AuthenticatedContent{
			WireFormat: one.wireFormat,
			Content:    *one.content,
			Auth:       FramedContentAuthData{Signature: signature},
		}, one.groupContext)
		if answered == nil || answered.Error() != preimage.Error() {
			t.Errorf("%s: the preimage refused with %v and the verifier answered %v; a structural refusal travels out of the verifier unchanged",
				name, preimage, answered)
		}
		if errors.Is(answered, errBadSignature) {
			t.Errorf("%s: a message no preimage could be built for was answered as a signature that does not verify (%v), which sends the caller to check a signature nothing checked",
				name, answered)
		}
	}

	// the signature half: every way this package can produce one that does not verify
	type framingForgery struct {
		what        string
		authContent *AuthenticatedContent
		against     []byte
	}
	forged := []framingForgery{}
	flipped := *signed.authContent
	flipped.Auth.Signature = bytes.Clone(signature)
	flipped.Auth.Signature[0] ^= 0x01
	forged = append(forged, framingForgery{"a signature with one bit flipped", &flipped, signed.groupContext})
	truncated := *signed.authContent
	truncated.Auth.Signature = bytes.Clone(signature)[:len(signature)-1]
	forged = append(forged, framingForgery{"a signature one octet short", &truncated, signed.groupContext})
	for _, empty := range emptyByteSpellings() {
		zero := *signed.authContent
		zero.Auth.Signature = empty.value
		forged = append(forged, framingForgery{"a signature that is " + empty.what, &zero, signed.groupContext})
	}
	// a signature over another epoch's preimage, which is the replay the group context is in
	// the preimage to stop, and a signature by a key that is not this one. Both are real
	// signatures: what fails is the preimage they cover and the key that made them.
	otherEpoch := bytes.Clone(signed.groupContext)
	otherEpoch[len(otherEpoch)-1] ^= 0xff
	elsewhere, err := SignAuthenticatedContent(signed.crypto, signed.priv, WireFormatPrivateMessage,
		framingTestMemberContent(), otherEpoch)
	if err != nil {
		t.Fatalf("sign under another epoch: %v", err)
	}
	forged = append(forged, framingForgery{"a signature over another epoch's preimage", elsewhere, signed.groupContext})
	strangerPriv, _, err := signed.crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("a second key pair: %v", err)
	}
	stranger, err := SignAuthenticatedContent(signed.crypto, strangerPriv, WireFormatPrivateMessage,
		framingTestMemberContent(), signed.groupContext)
	if err != nil {
		t.Fatalf("sign under another key: %v", err)
	}
	forged = append(forged, framingForgery{"a signature by a key that is not this one", stranger, signed.groupContext})

	for _, one := range forged {
		answered := VerifyAuthenticatedContent(signed.crypto, signed.pub, one.authContent, one.against)
		if answered != errFramedContentBadSignature {
			t.Errorf("%s: the verifier answered %v, want errFramedContentBadSignature itself; a caller that can tell these apart learns which of its guesses was closest",
				one.what, answered)
		}
	}
	if len(forged) < 5 {
		t.Fatalf("%d ways of failing the signature were run, and the empty spellings alone are three", len(forged))
	}
}

// ---------------------------------------------------------------------------
// AuthenticatedContentTBM and the membership tag
// ---------------------------------------------------------------------------

// framingSignedOfEveryContentType signs one message per REGISTERED content type and answers
// them keyed by it, with a commit's confirmation tag filled in the way its committer would.
//
// Derived against the registry rather than written as three rows, which is this package's rule
// after fourteen hand written class lists understated the class they named. The arms are not
// interchangeable here: a commit's FramedContentAuthData is a signature FOLLOWED BY a
// confirmation tag and every other arm's is a signature alone, so a preimage that stopped at
// the signature is invisible from an application message and visible from a commit. A fourth
// content type registered by a later task joins every sweep below by existing, and until
// somebody builds a message for it these fail rather than covering part of the registry
// quietly.
func framingSignedOfEveryContentType(t *testing.T, signed framingSigned) map[ContentType]*AuthenticatedContent {
	t.Helper()
	contents := map[ContentType]*FramedContent{
		ContentTypeApplication: framingTestMemberContent(),
		ContentTypeProposal:    framingTestProposalContent(),
		ContentTypeCommit:      framingTestCommitContent(),
	}
	registered := map[ContentType]string{}
	for name, code := range registryConstantsOfType(t, "ContentType") {
		registered[ContentType(code)] = name
	}
	built := map[ContentType]*AuthenticatedContent{}
	for contentType, name := range registered {
		content, held := contents[contentType]
		if !held {
			t.Fatalf("%s is a registered content type and no message is built for it, so every sweep reading this runs over a subset of the registry",
				name)
		}
		if content.ContentType != contentType {
			t.Fatalf("the message built for %s carries content type %d", name, content.ContentType)
		}
		authContent, err := SignAuthenticatedContent(signed.crypto, signed.priv,
			WireFormatPublicMessage, content, signed.groupContext)
		if err != nil {
			t.Fatalf("sign a %s: %v", name, err)
		}
		// a commit's auth data carries a confirmation tag as well as a signature, and the
		// encoder refuses to write one without it. The committer fills it in once it has
		// advanced the transcript; here it is a value of the provider's own tag width and
		// nothing more, because what these sweeps are about is that it is COVERED.
		if contentType == ContentTypeCommit {
			authContent.Auth.ConfirmationTag = bytes.Repeat([]byte{0x77}, signed.crypto.HashSize())
		}
		built[contentType] = authContent
	}
	for contentType := range contents {
		if _, isRegistered := registered[contentType]; !isRegistered {
			t.Fatalf("a message is built for content type %d, which no registry of this package holds", contentType)
		}
	}
	return built
}

// TestTheMembershipTagPreimageIsTheSignaturePreimageFollowedByTheAuthData holds the layout of
// AuthenticatedContentTBM at every registered content type.
//
// The two halves are asserted separately rather than as one byte comparison, because they fail
// for different reasons and a reader has to be told which. A preimage that does not BEGIN with
// the FramedContentTBS is one whose membership tag covers a different message than its
// signature does; a preimage whose tail is not the auth data is one whose membership tag does
// not cover the authenticators, which for a commit means the confirmation tag is outside the
// MAC and a tag can be lifted from one commit onto another.
//
// The auth data is required to be non empty, and that line is not decoration. Without it a
// preimage that stopped at the FramedContentTBS satisfies the prefix half, satisfies the tail
// half against an empty expectation, and reports PASS.
func TestTheMembershipTagPreimageIsTheSignaturePreimageFollowedByTheAuthData(t *testing.T) {
	signed := framingSignedMemberMessage(t)
	for contentType, authContent := range framingSignedOfEveryContentType(t, signed) {
		at := fmt.Sprintf("content type %d", contentType)
		tbm, err := AuthenticatedContentTBMBytes(authContent, signed.groupContext)
		if err != nil {
			t.Fatalf("%s: the tag preimage: %v", at, err)
		}
		tbs, err := FramedContentTBSBytes(authContent.WireFormat, &authContent.Content, signed.groupContext)
		if err != nil {
			t.Fatalf("%s: the signature preimage: %v", at, err)
		}
		w := syntax.NewWriter()
		if err := authContent.Auth.MarshalMLS(w, contentType); err != nil {
			t.Fatalf("%s: encode the auth data: %v", at, err)
		}
		auth, err := w.Bytes()
		if err != nil {
			t.Fatalf("%s: the auth data bytes: %v", at, err)
		}
		if len(auth) == 0 {
			t.Fatalf("%s: the auth data encoded to nothing, so the tail comparison below holds for a preimage that stops at the signature preimage",
				at)
		}
		if !bytes.HasPrefix(tbm, tbs) {
			t.Errorf("%s: the tag preimage is %x and does not begin with the signature preimage %x; a membership tag over a preimage that is not the signature's own covers a different message than the signature does",
				at, tbm, tbs)
			continue
		}
		if tail := tbm[len(tbs):]; !bytes.Equal(tail, auth) {
			t.Errorf("%s: the tag preimage carries %x after the signature preimage and the auth data is %x; RFC 9420 section 6.1 puts the FramedContentAuthData there, so a commit's confirmation tag is inside what the membership tag authenticates",
				at, tail, auth)
		}
	}
}

// TestTheMembershipTagPreimageBindsEveryByteOfTheGroupContext is the epoch binding, derived
// over the LENGTH of the context rather than sampled at a position somebody chose.
//
// What it refuses is the omission senderBindsGroupContext calls the most expensive one
// available here, one layer up: a TBM assembled without the group context is a membership tag
// that verifies in EVERY epoch of the group, so a proposal a member sent in epoch 4 is a
// proposal any peer can replay into epoch 9 and every receiver accepts. That preimage is well
// formed, it agrees with itself in both directions, and no round trip property in this package
// can see it.
//
// Every byte and not the epoch field alone, because the group id, the tree hash and the
// confirmed transcript hash are in there for reasons of their own -- two groups, two trees and
// two histories -- and a preimage that inlined a truncated context binds only some of them.
func TestTheMembershipTagPreimageBindsEveryByteOfTheGroupContext(t *testing.T) {
	signed := framingSignedMemberMessage(t)
	if len(signed.groupContext) == 0 {
		t.Fatal("the fixture's group context is empty, so the sweep below runs over nothing")
	}
	base, err := AuthenticatedContentTBMBytes(signed.authContent, signed.groupContext)
	if err != nil {
		t.Fatalf("the tag preimage: %v", err)
	}
	for at := range signed.groupContext {
		moved := bytes.Clone(signed.groupContext)
		moved[at] ^= 0xff
		tbm, err := AuthenticatedContentTBMBytes(signed.authContent, moved)
		if err != nil {
			t.Fatalf("byte %d of %d moved: %v", at, len(signed.groupContext), err)
		}
		if bytes.Equal(tbm, base) {
			t.Errorf("byte %d of the %d byte group context does not reach the tag preimage, so a membership tag taken under this epoch is a valid tag under a group context that differs there",
				at, len(signed.groupContext))
		}
	}
	// and the same statement in the direction a caller reaches by passing nothing: a member's
	// preimage cannot be built without one at all, rather than being built one field shorter.
	for _, empty := range emptyByteSpellings() {
		if _, err := AuthenticatedContentTBMBytes(signed.authContent, empty.value); !errors.Is(err, ErrMissingGroupContext) {
			t.Errorf("a member's tag preimage was built over a group context that is %s: got %v, want ErrMissingGroupContext",
				empty.what, err)
		}
	}
}

// TestTheMembershipTagPreimageBindsEveryByteOfTheAuthData is the other half, derived over the
// lengths of the authenticators the message actually carries.
//
// The fields are read off the VALUE rather than listed per content type: whatever a
// FramedContentAuthData is carrying at this arm is swept, so a task that gives that structure a
// third authenticator joins this sweep by filling it in. What the sweep refuses is a TBM built
// from the FramedContent rather than from the AuthenticatedContent -- the shape that reads like
// the obvious one, since the tag travels beside the content on the wire -- which authenticates
// neither the signature nor the confirmation tag.
//
// The commit arm is required to have been swept, because it is the only one that carries a
// confirmation tag and it is the arm the whole property is about.
func TestTheMembershipTagPreimageBindsEveryByteOfTheAuthData(t *testing.T) {
	signed := framingSignedMemberMessage(t)
	for contentType, authContent := range framingSignedOfEveryContentType(t, signed) {
		at := fmt.Sprintf("content type %d", contentType)
		base, err := AuthenticatedContentTBMBytes(authContent, signed.groupContext)
		if err != nil {
			t.Fatalf("%s: the tag preimage: %v", at, err)
		}
		swept := map[string]int{}
		for name, field := range map[string]*[]byte{
			"the signature":        &authContent.Auth.Signature,
			"the confirmation tag": &authContent.Auth.ConfirmationTag,
		} {
			original := bytes.Clone(*field)
			for position := range original {
				moved := bytes.Clone(original)
				moved[position] ^= 0xff
				*field = moved
				tbm, err := AuthenticatedContentTBMBytes(authContent, signed.groupContext)
				*field = original
				if err != nil {
					t.Fatalf("%s: byte %d of %s moved: %v", at, position, name, err)
				}
				if bytes.Equal(tbm, base) {
					t.Errorf("%s: byte %d of %s does not reach the tag preimage, so the membership tag does not cover it",
						at, position, name)
				}
				swept[name]++
			}
		}
		if swept["the signature"] == 0 {
			t.Fatalf("%s: the fixture carries no signature, so this sweep ran over nothing", at)
		}
		if contentType == ContentTypeCommit && swept["the confirmation tag"] == 0 {
			t.Fatalf("%s: the commit fixture carries no confirmation tag, so the one arm this sweep exists for was never run", at)
		}
	}
}

// TestTheMembershipTagPreimageBindsTheWireFormat runs the whole registry rather than the two
// code points a reader pictures, and asks for the preimages to be pairwise distinct.
//
// Distinctness rather than a layout assertion, because what the wire format is in the preimage
// FOR is that no two of them produce the same authenticated bytes: a PublicMessage replayed as
// a PrivateMessage is the substitution section 6.1 puts the field there to refuse. A TBM built
// under a wire format the caller named, or under a constant, is the same bytes for every entry
// of the registry and fails here.
func TestTheMembershipTagPreimageBindsTheWireFormat(t *testing.T) {
	signed := framingSignedMemberMessage(t)
	registered := registryConstantsOfType(t, "WireFormat")
	seen := map[string]string{}
	for name, code := range registered {
		lifted := *signed.authContent
		lifted.WireFormat = WireFormat(code)
		tbm, err := AuthenticatedContentTBMBytes(&lifted, signed.groupContext)
		if err != nil {
			t.Fatalf("%s: the tag preimage: %v", name, err)
		}
		if other, collided := seen[string(tbm)]; collided {
			t.Errorf("the tag preimage under %s is byte for byte the one under %s, so a membership tag over a %s is a valid membership tag over the same content sent as a %s",
				name, other, other, name)
			continue
		}
		seen[string(tbm)] = name
	}
	if len(seen) != len(registered) {
		t.Errorf("%d of the %d registered wire formats produced a distinct tag preimage", len(seen), len(registered))
	}
}

// TestVerifyMembershipTagRefusesEveryTagButItsOwn is ValSem007 and ValSem008, with every
// refusal derived over the length or the shape of the thing it alters.
//
// The sampled version of this test is the one this project has already been burned by twice: a
// suite that flips bit zero of byte zero is satisfied by a verifier that reads byte zero and
// stops, and a suite with no length case in it at all is satisfied by a verifier that accepts
// every truncation of a valid tag -- a forgery an attacker finds by trying tags one octet long.
// So the bit sweep is every bit of every byte, and the length sweep is every length shorter
// than its own as well as several longer.
//
// The absent tag is swept over all three spellings of absent, for emptyByteSpellings' reason: a
// guard written on == nil accepts the empty non nil slice a decoder hands back after reading an
// empty opaque<V>, which is a PublicMessage whose membership_tag field is present and empty.
func TestVerifyMembershipTagRefusesEveryTagButItsOwn(t *testing.T) {
	signed := framingSignedMemberMessage(t)
	membershipKey := bytes.Repeat([]byte{0x5a}, signed.crypto.HashSize())
	tag, err := ComputeMembershipTag(signed.crypto, membershipKey, signed.authContent, signed.groupContext)
	if err != nil {
		t.Fatalf("compute the tag: %v", err)
	}
	if len(tag) != signed.crypto.HashSize() {
		t.Fatalf("the tag is %d bytes and this provider's mac is %d", len(tag), signed.crypto.HashSize())
	}
	// the positive first: without it every refusal below is satisfied by a verifier that
	// refuses everything, which is the shape a suite of nothing but negatives cannot see.
	if err := verifyMembershipTag(signed.crypto, membershipKey, signed.authContent,
		signed.groupContext, tag); err != nil {
		t.Fatalf("the verifier refused the tag ComputeMembershipTag produced over the same message under the same key: %v", err)
	}
	for _, empty := range emptyByteSpellings() {
		if err := verifyMembershipTag(signed.crypto, membershipKey, signed.authContent,
			signed.groupContext, empty.value); !errors.Is(err, errMissingMembershipTag) {
			t.Errorf("a tag that is %s answered %v, want the ValSem007 sentinel", empty.what, err)
		}
	}
	for at := range tag {
		for bit := 0; bit < 8; bit++ {
			flipped := bytes.Clone(tag)
			flipped[at] ^= 1 << bit
			if err := verifyMembershipTag(signed.crypto, membershipKey, signed.authContent,
				signed.groupContext, flipped); !errors.Is(err, errBadMembershipTag) {
				t.Errorf("bit %d of byte %d of the tag flipped answered %v, want the ValSem008 sentinel", bit, at, err)
			}
		}
	}
	for n := 1; n < len(tag); n++ {
		if err := verifyMembershipTag(signed.crypto, membershipKey, signed.authContent,
			signed.groupContext, bytes.Clone(tag)[:n]); !errors.Is(err, errBadMembershipTag) {
			t.Errorf("a tag truncated to %d of %d bytes answered %v; a prefix comparison accepts every truncation of a valid tag",
				n, len(tag), err)
		}
	}
	// longer as well as shorter, and over a CLONE rather than an append onto the tag itself:
	// append on a slice with spare capacity writes through into the caller's array, which turns
	// a refusal row into a row that also moved the value every other row is built from.
	for n := 1; n <= 4; n++ {
		extended := append(bytes.Clone(tag), bytes.Repeat([]byte{0x00}, n)...)
		if err := verifyMembershipTag(signed.crypto, membershipKey, signed.authContent,
			signed.groupContext, extended); !errors.Is(err, errBadMembershipTag) {
			t.Errorf("a tag %d bytes longer than its own answered %v", n, err)
		}
	}
	// the neighbouring key, over every byte of it. confirmation_key and membership_key are
	// adjacent DeriveSecret calls over one parent, so they are the same width and a swap
	// produces a tag just as well formed; nothing about the SHAPE of an answer separates them.
	for at := range membershipKey {
		other := bytes.Clone(membershipKey)
		other[at] ^= 0xff
		if err := verifyMembershipTag(signed.crypto, other, signed.authContent,
			signed.groupContext, tag); !errors.Is(err, errBadMembershipTag) {
			t.Errorf("the tag verified under a key differing at byte %d of %d: %v", at, len(membershipKey), err)
		}
	}
	// the neighbouring epoch, which is what the group context is in the preimage for
	otherEpoch := bytes.Clone(signed.groupContext)
	otherEpoch[len(otherEpoch)-1] ^= 0xff
	if err := verifyMembershipTag(signed.crypto, membershipKey, signed.authContent,
		otherEpoch, tag); !errors.Is(err, errBadMembershipTag) {
		t.Errorf("the tag verified under another epoch's group context: %v", err)
	}
	// and a message no preimage can be assembled for is answered by the PREIMAGE's refusal
	// rather than by ValSem008, for VerifyAuthenticatedContent's reason: there is no comparison
	// to have failed, so telling the caller its tag did not verify sends it to check a tag
	// nothing checked.
	external := framingTestProposalContent()
	external.Sender = Sender{SenderType: SenderTypeExternal}
	lifted := &AuthenticatedContent{
		WireFormat: WireFormatPublicMessage,
		Content:    *external,
		Auth:       signed.authContent.Auth,
	}
	if err := verifyMembershipTag(signed.crypto, membershipKey, lifted,
		signed.groupContext, tag); !errors.Is(err, ErrUnexpectedGroupContext) {
		t.Errorf("a sender type that binds no group context answered %v, want the preimage's own refusal", err)
	}
	if err := verifyMembershipTag(signed.crypto, membershipKey, nil,
		signed.groupContext, tag); !errors.Is(err, errNilAuthenticatedContent) {
		t.Errorf("a nil message answered %v, want the nil message refusal", err)
	}
}

// TestTheMembershipTagPreimageIsTheOneThePublishedTagsWereTakenOver is the known answer test
// for this task, and it is the join nothing on this project had made.
//
// Everything else in this file is this package agreeing with itself. A preimage that inlined
// the group context with a length prefix, that omitted the wire format, that ordered its two
// halves the other way round, or that stopped at the FramedContent, computes a tag and verifies
// it back perfectly and fails only against another implementation. mlswg's message-protection
// corpus is that other implementation: it publishes an epoch's membership_key, the four
// GroupContext fields the epoch was framed under, and two PublicMessages whose membership_tag
// is MAC(membership_key, AuthenticatedContentTBM).
//
// Three separate things are compared here and each catches what the others do not.
//
// The bytes this task builds are held against the SPLICE p4's own known answer test rebuilds
// out of the published message -- version, wire format and FramedContent taken verbatim from
// the corpus, the group context inserted at the boundary the published body locates, the auth
// data taken from what is left once the trailing membership tag is removed. That reconstruction
// is a function of published bytes alone and shares no code with this one, so a disagreement
// names the preimage rather than the key.
//
// The tag is compared against the published one through THIS plan's ComputeMembershipTag and
// through p4's (*KeySchedule).MembershipTag, over the same preimage. That pair is the cross
// plan property nobody had checked: p5's note says p6 builds the TBM and passes the bytes, the
// two halves were written by different plans against a prose description of one structure, and
// until now nothing had put one into the other. A key schedule that verified its own tags and a
// framing layer that verified its own would both have been green.
//
// And the published tag is required to be REFUSED under the neighbouring epoch's context, so
// what passed above is the binding rather than a verifier that accepts what it is handed.
func TestTheMembershipTagPreimageIsTheOneThePublishedTagsWereTakenOver(t *testing.T) {
	entries := []messageProtectionKatEntry{}
	mustLoadAuthenticatedCorpus(t, messageProtectionKatFile, &entries)
	if len(entries) == 0 {
		t.Fatalf("%s parsed to no entries, so every comparison below would run over nothing", messageProtectionKatFile)
	}
	epochs := ksVectorEpochs(t)
	compared := 0
	matched := []CipherSuite{}
	for _, entry := range entries {
		suite := CipherSuite(entry.CipherSuite)
		if !IsRegisteredSuite(suite) {
			continue
		}
		matched = append(matched, suite)
		crypto := mustProvider(t, suite)
		nh := crypto.HashSize()
		suiteAt := fmt.Sprintf("%s suite %#04x", messageProtectionKatFile, uint16(suite))
		membershipKey := mustDecodeHex(t, suiteAt+" membership_key", entry.MembershipKey)
		if len(membershipKey) != nh {
			t.Fatalf("%s: the published membership_key is %d bytes and this suite's KDF.Nh is %d",
				suiteAt, len(membershipKey), nh)
		}
		context := func(epoch uint64) []byte {
			t.Helper()
			encoded, err := syntax.Marshal(&GroupContext{
				Version:                 ProtocolVersionMls10,
				CipherSuite:             suite,
				GroupId:                 mustDecodeHex(t, suiteAt+" group_id", entry.GroupId),
				Epoch:                   epoch,
				TreeHash:                mustDecodeHex(t, suiteAt+" tree_hash", entry.TreeHash),
				ConfirmedTranscriptHash: mustDecodeHex(t, suiteAt+" confirmed_transcript_hash", entry.ConfirmedTranscriptHash),
			})
			if err != nil {
				t.Fatalf("%s: encode the group context these messages were framed under: %v", suiteAt, err)
			}
			return encoded
		}
		groupContext := context(entry.Epoch)
		for _, message := range []struct {
			what string
			body string
			pub  string
		}{
			{what: "proposal_pub", body: entry.Proposal, pub: entry.ProposalPub},
			{what: "commit_pub", body: entry.Commit, pub: entry.CommitPub},
		} {
			at := suiteAt + " " + message.what
			publicMessage := mustDecodeHex(t, at, message.pub)
			authContent := framingPublishedPublicMessage(t, at, publicMessage)
			tbm, err := AuthenticatedContentTBMBytes(authContent, groupContext)
			if err != nil {
				t.Fatalf("%s: the tag preimage: %v", at, err)
			}
			spliced := authenticatedContentTbm(t, at, publicMessage,
				mustDecodeHex(t, at+" body", message.body), groupContext, nh)
			if !bytes.Equal(tbm, spliced) {
				t.Errorf("%s: AuthenticatedContentTBMBytes built %x, and splicing the published message at the boundary its own body locates gives %x. These are the bytes p4's tag functions consume, and the two plans wrote them from one prose description of section 6.1 without ever comparing them",
					at, tbm, spliced)
			}
			want := publishedTagAtTheTail(t, at, publicMessage, nh)
			got, err := ComputeMembershipTag(crypto, membershipKey, authContent, groupContext)
			if err != nil {
				t.Fatalf("%s: compute the tag: %v", at, err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s: ComputeMembershipTag = %x, and mlswg published %x. The tag is MAC(membership_key, AuthenticatedContentTBM) and nothing else; a preimage that agrees with itself agrees with no other implementation",
					at, got, want)
			}
			if err := verifyMembershipTag(crypto, membershipKey, authContent, groupContext, want); err != nil {
				t.Errorf("%s: the verifier refused the tag mlswg published for this key and this message: %v", at, err)
			}
			// p4's half of the join, over the preimage this task built
			schedule := ksScheduleForSuite(t, epochs, suite)
			installTheCorpusKey(t, at, &schedule.Secrets().Membership, membershipKey,
				schedule.MembershipTag(tbm), want)
			if fromSchedule := schedule.MembershipTag(tbm); !bytes.Equal(fromSchedule, want) {
				t.Errorf("%s: (*KeySchedule).MembershipTag over the preimage this task builds = %x, and mlswg published %x",
					at, fromSchedule, want)
			}
			if !schedule.VerifyMembershipTag(tbm, want) {
				t.Errorf("%s: (*KeySchedule).VerifyMembershipTag refused the published tag over the preimage this task builds", at)
			}
			if err := verifyMembershipTag(crypto, membershipKey, authContent,
				context(entry.Epoch+1), want); !errors.Is(err, errBadMembershipTag) {
				t.Errorf("%s: the published tag verified under the next epoch's group context: got %v, want the ValSem008 sentinel",
					at, err)
			}
			compared++
		}
	}
	if compared != membershipTagComparisons {
		t.Fatalf("%d published membership tags were reproduced, want %d; the loop matched %v",
			compared, membershipTagComparisons, matched)
	}
	if got := slices.Sorted(slices.Values(matched)); !slices.Equal(got, Suites()) {
		t.Fatalf("%s answered for %v and this package registers %v", messageProtectionKatFile, got, Suites())
	}
}

// ---------------------------------------------------------------------------
// guardrail 8 over the membership tag refusal
// ---------------------------------------------------------------------------

// membershipTagRefusal is one declaration that can answer a membership tag refusal, together
// with the parsed file it was read out of, because every rule below renders nodes of it back to
// source and a node rendered against the wrong file set gives the wrong positions.
//
// decides separates the half of the class that MAKES the decision from the half that carries
// somebody else's out. Both are in the class -- a refusal is a refusal to the caller wherever it
// was decided -- and they are held to different rules, because a rule about HOW a tag was
// compared is a rule about a body that compared one.
type membershipTagRefusal struct {
	name     string
	host     parsedSource
	function *ast.FuncDecl
	decides  bool
}

// membershipTagSource is one parsed file together with the path the class reports its
// declarations under.
type membershipTagSource struct {
	path   string
	parsed parsedSource
}

// membershipTagNames answers whether one expression mentions an identifier anywhere inside it.
//
// ANYWHERE, rather than as the whole of the expression, and that is the difference between a
// class and a spelling. `return errBadMembershipTag` and
// `return fmt.Errorf("%w: ...", errBadMembershipTag)` are one refusal to every caller -- errors.Is
// answers yes to both -- and the file this rule reads already writes its OWN refusals in the
// second shape. Measured: with the rule rendering the result and string comparing it to the
// sentinel's name, a declaration that decided the tag with a hand written byte loop and refused in
// the wrapping shape entered no class here and was reported by nothing in ./mls/... or
// ./message/....
func membershipTagNames(expression ast.Expr, sentinel string) bool {
	named := false
	ast.Inspect(expression, func(node ast.Node) bool {
		if identifier, isIdentifier := node.(*ast.Ident); isIdentifier && identifier.Name == sentinel {
			named = true
		}
		return !named
	})
	return named
}

// membershipTagRefusalReturns is every return that can carry one sentinel out of a node, rendered.
func membershipTagRefusalReturns(parsed parsedSource, node ast.Node, sentinel string) []string {
	found := []string{}
	ast.Inspect(node, func(inner ast.Node) bool {
		returns, isReturn := inner.(*ast.ReturnStmt)
		if !isReturn {
			return true
		}
		for _, result := range returns.Results {
			if membershipTagNames(result, sentinel) {
				found = append(found, parsed.render(returns))
				break
			}
		}
		return true
	})
	return found
}

// membershipTagCalleeNames is every name one declaration calls, as the call site spells it: the
// bare identifier for a function of this package and the selected name for a method.
//
// The selected half over reports and is meant to. A method sharing a name with a member of the
// class pulls its caller in, which costs that caller the propagation rule and nothing else; the
// direction that loses a mutant is the other one.
func membershipTagCalleeNames(function *ast.FuncDecl) []string {
	names := []string{}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		switch callee := call.Fun.(type) {
		case *ast.Ident:
			names = append(names, callee.Name)
		case *ast.SelectorExpr:
			names = append(names, callee.Sel.Name)
		}
		return true
	})
	return names
}

// membershipTagRefusalsIn is the class over a set of parsed files: every declaration that can
// answer the ValSem008 refusal, whether it decides one or carries one out.
//
// Derived off the SENTINEL rather than off a name, and closed under CALLS rather than stopping at
// the declarations that name it, which is the whole of why this is a class. The rules below are
// about how that refusal is REACHED and about what happens to it once it exists, so the members
// are every declaration either question can be asked of, and p7's receive path joins by refusing
// or by calling something that refuses rather than by somebody remembering to add it here. The one
// shape that escapes the derivation -- a verifier that stopped refusing at all -- empties the class
// rather than passing it, and an empty class is fatal below.
//
// The fixed point is not decoration. p7 will reach this refusal through its own helpers, and a
// class that read only the direct callers would drop the declaration two hops out exactly as the
// name comparison dropped the wrapping shape.
func membershipTagRefusalsIn(sources []membershipTagSource, sentinel string) []membershipTagRefusal {
	candidates := []membershipTagRefusal{}
	for _, source := range sources {
		for _, declaration := range source.parsed.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			candidates = append(candidates, membershipTagRefusal{
				name:     source.path + ": " + function.Name.Name,
				host:     source.parsed,
				function: function,
				decides:  len(membershipTagRefusalReturns(source.parsed, function.Body, sentinel)) != 0,
			})
		}
	}
	inClass := map[string]bool{}
	for _, candidate := range candidates {
		if candidate.decides {
			inClass[candidate.function.Name.Name] = true
		}
	}
	for grew := true; grew; {
		grew = false
		for _, candidate := range candidates {
			if inClass[candidate.function.Name.Name] {
				continue
			}
			for _, callee := range membershipTagCalleeNames(candidate.function) {
				if !inClass[callee] {
					continue
				}
				inClass[candidate.function.Name.Name] = true
				grew = true
				break
			}
		}
	}
	found := []membershipTagRefusal{}
	for _, candidate := range candidates {
		if inClass[candidate.function.Name.Name] {
			found = append(found, candidate)
		}
	}
	return found
}

// membershipTagRoutingFaults reads one declaration for every way it can decide a membership tag
// other than the one guardrail 8 permits, and for every way it can lose one it was handed, each
// answered as "kind: detail".
//
// The KIND is what the control compares, so each half of the rule has to be the only thing
// reporting some member of that fixture. A rule whose halves cannot be told apart is a rule that
// can have a half deleted with its control still matching exactly what it wants.
func membershipTagRoutingFaults(parsed parsedSource, function *ast.FuncDecl, sentinel string,
	class []membershipTagRefusal) []string {

	faults := []string{}
	if len(membershipTagRefusalReturns(parsed, function.Body, sentinel)) != 0 {
		faults = append(faults, membershipTagDecisionFaults(parsed, function, sentinel)...)
	}
	return append(faults, membershipTagPropagationFaults(parsed, function, class)...)
}

// membershipTagDecisionFaults judges a body that DECIDES the refusal: what it decided with, and
// whether it walked the bytes itself.
//
// The loop clause is the one that is not about a comparator name, and it is here because
// constant_time_test.go's own header says what that gate cannot see: "a comparison written as a
// byte loop in this package's own source names no comparator and is in no class derived from
// imports". That blind spot is closed for this refusal by refusing the loop itself, which a
// decision written as one cannot do without.
//
// It is asked only of a decider, and that is the boundary rather than an omission. A declaration
// that carries somebody else's refusal out compares nothing, and a receive path is a loop:
// reporting the loop there would be a fault about a comparison that is not in the body.
func membershipTagDecisionFaults(parsed parsedSource, function *ast.FuncDecl, sentinel string) []string {
	parameters := []string{}
	if function.Type.Params != nil {
		for _, field := range function.Type.Params.List {
			for _, name := range field.Names {
				parameters = append(parameters, name.Name)
			}
		}
	}
	faults := []string{}
	refusals := len(membershipTagRefusalReturns(parsed, function.Body, sentinel))
	guarded := 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		branch, isIf := node.(*ast.IfStmt)
		if !isIf {
			return true
		}
		inside := len(membershipTagRefusalReturns(parsed, branch.Body, sentinel))
		if inside == 0 {
			return true
		}
		guarded += inside
		faults = append(faults, membershipTagGuardFaults(parsed, branch.Cond, parameters)...)
		return true
	})
	if guarded < refusals {
		faults = append(faults, fmt.Sprintf("unguarded: %d of its %d refusals are reached from no condition at all",
			refusals-guarded, refusals))
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch node.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			faults = append(faults, "loop: it walks the bytes itself, and a comparison written as a loop names no comparator for any import derived gate to find")
		}
		return true
	})
	return faults
}

// membershipTagErrorResultAt is the position an error comes back at in one declaration's results,
// or -1 for a declaration that cannot report one.
func membershipTagErrorResultAt(member membershipTagRefusal) int {
	if member.function.Type.Results == nil {
		return -1
	}
	at := 0
	for _, result := range member.function.Type.Results.List {
		if member.host.render(result.Type) == "error" {
			return at
		}
		width := len(result.Names)
		if width == 0 {
			width = 1
		}
		at += width
	}
	return -1
}

// membershipTagPropagationFaults is guardrail 7 over the same refusal: a declaration that reaches
// a member of the class must not lose the answer.
//
// This is the half the decision rules cannot state, and p7 is the caller it is written for. A
// receive path that reaches verifyMembershipTag and throws the error away applies a proposal or a
// commit that no member of the group sent, and it does that with a body in which the sanctioned
// comparison is the only comparison there is -- so every rule above reports it clean. The doc
// comment on verifyMembershipTag writes the obligation out in prose, "p7 MUST RETURN on this
// refusal rather than logging it and continuing"; this is where the prose is measured.
//
// Two ways to lose it and both are syntax. A call written as a statement of its own binds no error
// at all. A call whose error result is assigned to the blank identifier binds it to nothing, which
// is the spelling that compiles and reads like a decision. And a declaration that reaches one of
// these while answering no error of its own cannot carry the refusal out however the call is
// written, so that is its own kind rather than a second report of the first.
func membershipTagPropagationFaults(parsed parsedSource, function *ast.FuncDecl,
	class []membershipTagRefusal) []string {

	reached := func(call *ast.CallExpr) (membershipTagRefusal, bool) {
		name := ""
		switch callee := call.Fun.(type) {
		case *ast.Ident:
			name = callee.Name
		case *ast.SelectorExpr:
			name = callee.Sel.Name
		}
		for _, member := range class {
			if member.function.Name.Name == name && member.function != function {
				return member, true
			}
		}
		return membershipTagRefusal{}, false
	}
	answersAnError := false
	if function.Type.Results != nil {
		for _, result := range function.Type.Results.List {
			if parsed.render(result.Type) == "error" {
				answersAnError = true
			}
		}
	}
	faults := []string{}
	carried := []string{}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch statement := node.(type) {
		case *ast.ExprStmt:
			call, isCall := statement.X.(*ast.CallExpr)
			if !isCall {
				return true
			}
			member, isMember := reached(call)
			if !isMember || membershipTagErrorResultAt(member) < 0 {
				return true
			}
			carried = append(carried, member.function.Name.Name)
			faults = append(faults, "discarded: it calls "+member.function.Name.Name+
				" as a statement of its own, so the refusal is bound to nothing")
		case *ast.AssignStmt:
			if len(statement.Rhs) != 1 {
				return true
			}
			call, isCall := statement.Rhs[0].(*ast.CallExpr)
			if !isCall {
				return true
			}
			member, isMember := reached(call)
			if !isMember {
				return true
			}
			at := membershipTagErrorResultAt(member)
			if at < 0 || at >= len(statement.Lhs) {
				return true
			}
			carried = append(carried, member.function.Name.Name)
			if target, isIdentifier := statement.Lhs[at].(*ast.Ident); isIdentifier && target.Name == "_" {
				faults = append(faults, "discarded: it assigns "+member.function.Name.Name+
					"'s refusal to the blank identifier")
			}
		}
		return true
	})
	if len(carried) != 0 && !answersAnError {
		faults = append(faults, "unanswerable: it reaches "+strings.Join(slices.Compact(carried), ", ")+
			" and answers no error of its own, so no spelling of the call could carry the refusal out")
	}
	return faults
}

// membershipTagGuardFaults reads the condition one refusal is reached from.
func membershipTagGuardFaults(parsed parsedSource, condition ast.Expr, parameters []string) []string {
	negated, isUnary := condition.(*ast.UnaryExpr)
	if !isUnary || negated.Op != token.NOT {
		return []string{"guard: it refuses on " + parsed.render(condition) +
			" rather than on a MacVerify that answered false"}
	}
	call, isCall := negated.X.(*ast.CallExpr)
	if !isCall {
		return []string{"guard: it refuses on " + parsed.render(condition) +
			" rather than on a MacVerify that answered false"}
	}
	selector, isSelector := call.Fun.(*ast.SelectorExpr)
	if !isSelector || selector.Sel.Name != "MacVerify" {
		return []string{"guard: it refuses on " + parsed.render(condition) +
			", and guardrail 8 says a tag comparison is CryptoProvider.MacVerify and nothing else"}
	}
	faults := []string{}
	base, isIdentifier := selector.X.(*ast.Ident)
	if !isIdentifier || !slices.Contains(parameters, base.Name) {
		faults = append(faults, "provider: it verifies through "+parsed.render(selector.X)+
			", which is not a provider it was handed")
	}
	if len(call.Args) != 3 {
		return append(faults, fmt.Sprintf("arity: it calls MacVerify with %d arguments", len(call.Args)))
	}
	for at, argument := range call.Args {
		if _, isWhole := argument.(*ast.Ident); !isWhole {
			faults = append(faults, fmt.Sprintf("argument: it passes %s at MacVerify position %d, which is not the whole of a value it holds",
				parsed.render(argument), at))
		}
	}
	if parsed.render(call.Args[1]) == parsed.render(call.Args[2]) {
		faults = append(faults, "self: it compares the tag against itself rather than against a mac over the preimage")
	}
	return faults
}

// membershipTagRoutingControl declares one of each shape the rules above have to tell apart: the
// sanctioned body, the two comparators a ban list would have had to think of, the byte loop that
// carries no comparator at all, a prefix of the tag pushed through the sanctioned call, a tag
// compared against itself, a provider the function was never handed, a refusal reached from no
// condition, and then the five shapes that are about the refusal AFTER it exists -- the byte loop
// whose refusal is WRAPPED rather than bare, a caller that carries the refusal out, and the three
// ways to lose one.
//
// Every one is here because a control that does not DISCRIMINATE its own rule issues a broken
// matcher exactly the clean bill a working one issues. hmac.Equal is in the fixture deliberately:
// it is constant time and it is still wrong, because guardrail 8 names
// crypto/subtle.ConstantTimeCompare reached through CryptoProvider.MacVerify specifically, and a
// second comparison site is a second place the length refusal can be dropped.
//
// The wrapping and propagating shapes are here because they were measured to be outside the class
// the earlier rule derived: the rule rendered each return and string compared it to the sentinel's
// name, so `fmt.Errorf("%w: p7", errBadMembershipTag)` and `return err` were both invisible, and a
// variable time comparison written in the first of them was caught by nothing in ./mls/... or
// ./message/....
const membershipTagRoutingControl = `package control

func VerifiesThroughTheProvider(crypto CryptoProvider, key []byte, data []byte, tag []byte) error {
	if !crypto.MacVerify(key, data, tag) {
		return errBadMembershipTag
	}
	return nil
}

func VerifiesWithBytesEqual(crypto CryptoProvider, key []byte, data []byte, tag []byte) error {
	if !bytes.Equal(crypto.Mac(key, data), tag) {
		return errBadMembershipTag
	}
	return nil
}

func VerifiesWithHmacEqual(crypto CryptoProvider, key []byte, data []byte, tag []byte) error {
	if !hmac.Equal(crypto.Mac(key, data), tag) {
		return errBadMembershipTag
	}
	return nil
}

func VerifiesWithAByteLoop(crypto CryptoProvider, key []byte, data []byte, tag []byte) error {
	mine := crypto.Mac(key, data)
	same := len(mine) == len(tag)
	for at := range tag {
		if at < len(mine) && mine[at] != tag[at] {
			same = false
		}
	}
	if !same {
		return errBadMembershipTag
	}
	return nil
}

func VerifiesAPrefixOfTheTag(crypto CryptoProvider, key []byte, data []byte, tag []byte) error {
	if !crypto.MacVerify(key, data, tag[:1]) {
		return errBadMembershipTag
	}
	return nil
}

func VerifiesTheTagAgainstItself(crypto CryptoProvider, key []byte, data []byte, tag []byte) error {
	if !crypto.MacVerify(key, tag, tag) {
		return errBadMembershipTag
	}
	return nil
}

func VerifiesThroughAProviderItWasNotGiven(crypto CryptoProvider, key []byte, data []byte, tag []byte) error {
	if !elsewhere.MacVerify(key, data, tag) {
		return errBadMembershipTag
	}
	return nil
}

func RefusesWithNoConditionAtAll(crypto CryptoProvider, key []byte, data []byte, tag []byte) error {
	crypto.MacVerify(key, data, tag)
	return errBadMembershipTag
}

func WrapsTheSentinelAfterAByteLoop(crypto CryptoProvider, key []byte, data []byte, tag []byte) error {
	mine := crypto.Mac(key, data)
	same := len(mine) == len(tag)
	for at := range tag {
		if at < len(mine) && mine[at] != tag[at] {
			same = false
		}
	}
	if !same {
		return fmt.Errorf("%w: the wrapping shape", errBadMembershipTag)
	}
	return nil
}

func PropagatesTheRefusal(crypto CryptoProvider, key []byte, data []byte, tag []byte) error {
	if err := VerifiesThroughTheProvider(crypto, key, data, tag); err != nil {
		return err
	}
	return nil
}

func DiscardsTheRefusal(crypto CryptoProvider, key []byte, data []byte, tag []byte) error {
	VerifiesThroughTheProvider(crypto, key, data, tag)
	return nil
}

func BlanksTheRefusal(crypto CryptoProvider, key []byte, data []byte, tag []byte) error {
	_ = VerifiesThroughTheProvider(crypto, key, data, tag)
	return nil
}

func CannotAnswerTheRefusal(crypto CryptoProvider, key []byte, data []byte, tag []byte) {
	VerifiesThroughTheProvider(crypto, key, data, tag)
}
`

// membershipTagRoutingControlFaults is the kind of fault each control declaration must draw,
// written out here rather than derived, because a control is the one thing in a derived gate
// that cannot be derived from the rule it controls.
var membershipTagRoutingControlFaults = map[string][]string{
	"VerifiesThroughTheProvider":            {},
	"VerifiesWithBytesEqual":                {"guard"},
	"VerifiesWithHmacEqual":                 {"guard"},
	"VerifiesWithAByteLoop":                 {"guard", "loop"},
	"VerifiesAPrefixOfTheTag":               {"argument"},
	"VerifiesTheTagAgainstItself":           {"self"},
	"VerifiesThroughAProviderItWasNotGiven": {"provider"},
	"RefusesWithNoConditionAtAll":           {"unguarded"},
	// the wrapping shape, which is a member of the class only because the rule reads the whole
	// return expression rather than its rendering
	"WrapsTheSentinelAfterAByteLoop": {"guard", "loop"},
	// and the four propagating shapes, which are members only because the class is closed under
	// calls. The first must draw NOTHING, or the rule reports every caller and says nothing.
	"PropagatesTheRefusal":   {},
	"DiscardsTheRefusal":     {"discarded"},
	"BlanksTheRefusal":       {"discarded"},
	"CannotAnswerTheRefusal": {"discarded", "unanswerable"},
}

// TestEveryMembershipTagRefusalIsDecidedByMacVerifyAndNothingElse is guardrails 8 and 7 over this
// task's refusal, read off the source rather than off an input.
//
// No behavioural test in this file can see this. A verifier that compared with bytes.Equal, or
// with a byte loop of its own, answers exactly what this one answers for every input above: the
// timing leak and the dropped length refusal are properties of HOW the answer was reached, and
// the answer is identical. constant_time_test.go reads every comparison in this package's source
// against a class derived from its imports and catches the named comparators; what its own header
// says it cannot catch is the loop, and this is where that is closed for the one refusal that
// decides whether a message no member sent is applied to the group.
func TestEveryMembershipTagRefusalIsDecidedByMacVerifyAndNothingElse(t *testing.T) {
	const sentinel = "errBadMembershipTag"
	// the control first: a rule that has stopped matching issues the real source exactly the
	// clean bill a working one issues
	control := mustParseText(t, "the membership tag routing control", membershipTagRoutingControl)
	controlClass := membershipTagRefusalsIn([]membershipTagSource{{path: "control", parsed: control}}, sentinel)
	reported := map[string][]string{}
	for _, member := range controlClass {
		kinds := []string{}
		for _, fault := range membershipTagRoutingFaults(control, member.function, sentinel, controlClass) {
			kind, _, named := strings.Cut(fault, ": ")
			if !named {
				t.Fatalf("the rule answered %q, which carries no kind for the control to compare", fault)
			}
			if !slices.Contains(kinds, kind) {
				kinds = append(kinds, kind)
			}
		}
		slices.Sort(kinds)
		reported[member.function.Name.Name] = kinds
	}
	if len(reported) != len(membershipTagRoutingControlFaults) {
		t.Fatalf("the class read %v out of the control and the control declares %d bodies that refuse; a body it does not read is a shape the real source can be written in",
			slices.Sorted(maps.Keys(reported)), len(membershipTagRoutingControlFaults))
	}
	for _, name := range slices.Sorted(maps.Keys(membershipTagRoutingControlFaults)) {
		got, read := reported[name]
		if !read {
			t.Errorf("the class did not read %s out of the control", name)
			continue
		}
		if want := membershipTagRoutingControlFaults[name]; !slices.Equal(got, want) {
			t.Errorf("the rule reports %s with %v, want %v; a half of it that reports nothing of its own can be deleted with this control still matching",
				name, got, want)
		}
	}

	// and then this package's own source
	sources := []membershipTagSource{}
	for _, path := range packageLevelFunctions(t).files {
		sources = append(sources, membershipTagSource{path: path, parsed: mustParseSource(t, path)})
	}
	class := membershipTagRefusalsIn(sources, sentinel)
	deciders := 0
	for _, member := range class {
		if member.decides {
			deciders++
		}
	}
	if deciders == 0 {
		t.Fatalf("no declaration of this package's non test source answers %s, and this task lands one, so this gate is demanding nothing",
			sentinel)
	}
	for _, member := range class {
		for _, fault := range membershipTagRoutingFaults(member.host, member.function, sentinel, class) {
			t.Errorf("%s: %s", member.name, fault)
		}
	}
	t.Logf("%d declaration(s) can answer %s: %d decide one through CryptoProvider.MacVerify alone, and %d carry one out",
		len(class), sentinel, deciders, len(class)-deciders)
}

// ---------------------------------------------------------------------------
// the membership_key itself, and the order the two doors judge their arguments in
// ---------------------------------------------------------------------------

// membershipTagDoorNames is every declaration of this package's non test source that takes a
// membership_key, read off the parameter rather than listed.
//
// The class is the parameter NAME because that is what the doors share and what a third one would
// share: RFC 9420 section 6.2 has one key, and a declaration that takes it is a declaration that
// can mac under it. A gate whose table named two functions is a gate a third door gets written
// beside -- which is the shape of the finding this exists for, since ComputeMembershipTag and
// verifyMembershipTag both accepted a key p4's own door refuses.
func membershipTagDoorNames(t *testing.T) []string {
	t.Helper()
	names := []string{}
	for _, path := range packageLevelFunctions(t).files {
		parsed := mustParseSource(t, path)
		for _, declaration := range parsed.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Type.Params == nil {
				continue
			}
			for _, field := range function.Type.Params.List {
				for _, parameter := range field.Names {
					if parameter.Name == "membershipKey" {
						names = append(names, function.Name.Name)
					}
				}
			}
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) == 0 {
		t.Fatal("no declaration of this package's non test source takes a membershipKey, so this gate demands nothing")
	}
	return names
}

// membershipTagKeyRefusal is one shape of membership_key no tag may be taken under, with the
// sentinel both doors must answer for it.
type membershipTagKeyRefusal struct {
	what     string
	key      []byte
	sentinel error
}

// membershipTagUnusableKeys is every such shape, derived over the provider's own KDF.Nh rather
// than written at 32 octets.
//
// The width sweep is every length from nothing up to twice its own rather than one short key and
// one long one, for TestVerifyMembershipTagRefusesEveryTagButItsOwn's reason: a guard that read
// the first byte of the length, or that refused only what is shorter, passes a sampled sweep and
// this project has shipped exactly that twice.
//
// The last row is not a length case at all and it is the row this gate exists for. An epoch that
// has left PastEpochWindow is zeroized IN PLACE, so its membership_key is still KDF.Nh bytes and
// every length check in the world clears it, while a mac under KDF.Nh zero bytes is publicly
// computable: any party can forge a membership tag the receiver would accept, and that tag is the
// only authentication a member's PublicMessage carries besides the signature.
func membershipTagUnusableKeys(nh int) []membershipTagKeyRefusal {
	rows := []membershipTagKeyRefusal{}
	for _, empty := range emptyByteSpellings() {
		rows = append(rows, membershipTagKeyRefusal{
			what:     "a key that is " + empty.what,
			key:      empty.value,
			sentinel: ErrSecretLength,
		})
	}
	for n := 1; n <= 2*nh; n++ {
		if n == nh {
			continue
		}
		rows = append(rows, membershipTagKeyRefusal{
			what:     fmt.Sprintf("a key %d bytes wide and not %d", n, nh),
			key:      bytes.Repeat([]byte{0x6b}, n),
			sentinel: ErrSecretLength,
		})
	}
	rows = append(rows, membershipTagKeyRefusal{
		what:     fmt.Sprintf("the %d zero bytes an erased epoch leaves behind", nh),
		key:      make([]byte, nh),
		sentinel: ErrEpochErased,
	})
	return rows
}

// TestBothDoorsIntoSection62RefuseEveryKeyNoTagMayBeTakenUnder is the membership_key half of RFC
// 9420 section 6.2, and it is the half nothing observed.
//
// The finding it lands: ComputeMembershipTag and verifyMembershipTag took a key of ANY length and
// ANY content. Over the erased epoch's key -- KDF.Nh zero bytes, which is what
// PastEpochWindow's zeroize leaves behind and what the length can never see -- p6 produced a tag
// and accepted it back, while p4's (*KeySchedule).MembershipTag and VerifyMembershipTag refused
// the identical key through secretIsLive. Two doors into one rule, one of them guarded, and the
// doc comment on the unguarded one steering p7 toward it.
//
// Both halves are derived. The DOORS come off the parameter name, so a third one is swept by
// existing rather than by being added to a table; and which keys are unusable comes off p4's OWN
// predicate rather than off an opinion here -- every row is asserted to be a key secretIsLive
// calls dead before it is asked of p6, so the two plans are held to one class rather than to two
// lists that agree today.
//
// The positive row is not decoration. Without it every refusal below is satisfied by a door that
// refuses everything, which is the shape a sweep of nothing but negatives cannot see.
func TestBothDoorsIntoSection62RefuseEveryKeyNoTagMayBeTakenUnder(t *testing.T) {
	signed := framingSignedMemberMessage(t)
	sealed := framingSealedMemberProposal(t)
	nh := signed.crypto.HashSize()
	if sealed.crypto.HashSize() != nh {
		t.Fatalf("the two fixtures run at KDF.Nh %d and %d, so one set of key widths cannot be swept through both",
			nh, sealed.crypto.HashSize())
	}
	live := bytes.Repeat([]byte{0x5a}, nh)
	tag, err := ComputeMembershipTag(signed.crypto, live, signed.authContent, signed.groupContext)
	if err != nil {
		t.Fatalf("compute the tag every row below is run against: %v", err)
	}
	doors := map[string]func(t *testing.T, key []byte) error{
		"ComputeMembershipTag": func(t *testing.T, key []byte) error {
			answered, err := ComputeMembershipTag(signed.crypto, key, signed.authContent, signed.groupContext)
			// a refusal that also hands back bytes is the shape this project shipped once: the
			// caller reads the answer, the error goes to a log, and a tag derived from nothing
			// travels.
			if err != nil && answered != nil {
				t.Errorf("ComputeMembershipTag refused with %v and handed back %x anyway", err, answered)
			}
			return err
		},
		// section 6.2's two wire format doors, which reach the key through the two above. They are
		// swept here because the class is the PARAMETER, not the pair somebody wrote a table for:
		// each is a declaration a caller can hand an erased epoch's key to, and each has to refuse
		// it rather than mac under a run of zeros any party can compute.
		//
		// Both rows run over a message sealed for the PUBLIC wire format and carrying a proposal,
		// because ValSem005 refuses an application message here and the seal refuses any other wire
		// format -- the fixture the two rows above use is a private-format application message and
		// would be refused by the rule under test rather than by the key.
		"SealPublicMessage": func(t *testing.T, key []byte) error {
			message, err := SealPublicMessage(sealed.crypto, key, sealed.authContent, sealed.groupContext)
			// a refusal that also hands back a message is ComputeMembershipTag's shape one layer
			// out: the caller reads the answer, the error goes to a log, and a public message
			// travels carrying a tag derived from nothing.
			if err != nil && message != nil {
				t.Errorf("SealPublicMessage refused with %v and handed back a message carrying %x anyway",
					err, message.MembershipTag)
			}
			return err
		},
		"OpenPublicMessage": func(t *testing.T, key []byte) error {
			opened, err := OpenPublicMessage(sealed.crypto, key, sealed.message,
				StaticSignatureKey(sealed.pub), sealed.groupContext)
			if err != nil && opened != nil {
				t.Errorf("OpenPublicMessage refused with %v and handed back an authenticated content anyway", err)
			}
			return err
		},
		"verifyMembershipTag": func(t *testing.T, key []byte) error {
			return verifyMembershipTag(signed.crypto, key, signed.authContent, signed.groupContext, tag)
		},
	}
	if got, want := slices.Sorted(maps.Keys(doors)), membershipTagDoorNames(t); !slices.Equal(got, want) {
		t.Fatalf("this gate runs %v and this package's non test source takes a membership key at %v; a door with no row is a door with no guard",
			got, want)
	}
	// p4's own predicate is what says which keys are unusable rather than this test's opinion of
	// them. secretIsLive is the guard (*KeySchedule).MembershipTag and VerifyMembershipTag refuse
	// through, and the whole of the finding was that section 6.2's other door never asked.
	schedule := &KeySchedule{crypto: signed.crypto}
	if !schedule.secretIsLive(live) {
		t.Fatalf("p4's predicate calls the key every positive row is taken under erased, so the rows below compare two different classes")
	}
	for _, name := range slices.Sorted(maps.Keys(doors)) {
		door := doors[name]
		if err := door(t, live); err != nil {
			t.Errorf("%s refused a live key of the provider's own width: %v", name, err)
		}
		for _, refusal := range membershipTagUnusableKeys(nh) {
			if schedule.secretIsLive(refusal.key) {
				t.Errorf("%s: p4's secretIsLive calls %s live, so this row asks the two plans for different things",
					name, refusal.what)
				continue
			}
			answered := door(t, refusal.key)
			if !errors.Is(answered, refusal.sentinel) {
				t.Errorf("%s over %s answered %v, want %v", name, refusal.what, answered, refusal.sentinel)
			}
			// and it is refused as what it is. A key the RECEIVER got wrong answered as ValSem007
			// or ValSem008 sends the caller to look at a message that was never the problem, and
			// a validator mapping sentinels to codes would report a rule the sender did not fail.
			if errors.Is(answered, errBadMembershipTag) || errors.Is(answered, errMissingMembershipTag) {
				t.Errorf("%s over %s answered a ValSem code about the MESSAGE (%v), and what was wrong was the receiver's own key",
					name, refusal.what, answered)
			}
		}
	}
}

// TestTheAbsentMembershipTagIsRefusedAheadOfEveryPreimageThatCannotBeBuilt is the ORDER of
// verifyMembershipTag's first two message guards, which its own comment states and which nothing
// observed.
//
// The order is invisible from every other test in this file. A tagless message whose preimage
// assembles answers ValSem007 whichever side of the AuthenticatedContentTBMBytes call the guard is
// written on, so what separates the two orders is exactly the input that is BOTH tagless and
// unbuildable -- and there was none. Measured: the guard moved below the preimage build left the
// whole of ./mls/... green.
//
// What the order is worth. A receiver that built the preimage first answers a message carrying no
// membership tag at all with ErrUnknownSenderType or ErrMissingGroupContext, which is the
// preimage's complaint about a structure nobody was going to authenticate; the rule that actually
// refused the message is ValSem007, and a validator mapping sentinels to ValSem codes would have
// none for it. It also does the assembly for a message that could not have been accepted however
// it assembled.
//
// The class is framingStructuralPreimageRefusals', so a sender type or a wire format a later task
// registers joins by existing, and each row is run over all three spellings of an absent tag for
// emptyByteSpellings' reason.
func TestTheAbsentMembershipTagIsRefusedAheadOfEveryPreimageThatCannotBeBuilt(t *testing.T) {
	signed := framingSignedMemberMessage(t)
	membershipKey := bytes.Repeat([]byte{0x5a}, signed.crypto.HashSize())
	tag, err := ComputeMembershipTag(signed.crypto, membershipKey, signed.authContent, signed.groupContext)
	if err != nil {
		t.Fatalf("compute the tag the discriminating half is run with: %v", err)
	}
	structural := framingStructuralPreimageRefusals(t)
	for _, name := range slices.Sorted(maps.Keys(structural)) {
		one := structural[name]
		lifted := &AuthenticatedContent{
			WireFormat: one.wireFormat,
			Content:    *one.content,
			Auth:       signed.authContent.Auth,
		}
		// the discriminator first: carrying a tag, this row has to REACH the preimage and be
		// answered by its refusal verbatim. Without that half every assertion below is satisfied
		// by a verifier that answers ValSem007 to everything.
		_, preimage := AuthenticatedContentTBMBytes(lifted, one.groupContext)
		if preimage == nil {
			t.Errorf("%s: the preimage was assembled, so this row states nothing about an ordering", name)
			continue
		}
		if answered := verifyMembershipTag(signed.crypto, membershipKey, lifted, one.groupContext,
			tag); answered == nil || answered.Error() != preimage.Error() {
			t.Errorf("%s carrying a tag answered %v and the preimage refused with %v", name, answered, preimage)
		}
		for _, empty := range emptyByteSpellings() {
			answered := verifyMembershipTag(signed.crypto, membershipKey, lifted, one.groupContext, empty.value)
			if !errors.Is(answered, errMissingMembershipTag) {
				t.Errorf("%s carrying a tag that is %s answered %v, want the ValSem007 sentinel: the absent tag is refused before the preimage is built",
					name, empty.what, answered)
			}
		}
	}
	// the nil message is the preimage's other refusal and no row above can carry it, since a nil
	// authenticated content has no wire format to key one on.
	for _, empty := range emptyByteSpellings() {
		answered := verifyMembershipTag(signed.crypto, membershipKey, nil, signed.groupContext, empty.value)
		if !errors.Is(answered, errMissingMembershipTag) {
			t.Errorf("a nil message carrying a tag that is %s answered %v, want the ValSem007 sentinel",
				empty.what, answered)
		}
	}
}

// ---------------------------------------------------------------------------
// what the commentary claims about the gates
// ---------------------------------------------------------------------------

// The gate this package's commentary cites as the one that reads every comparison it ships. Held
// as the string the prose writes rather than as a reference to the function, because what is being
// checked is whether the prose names something that exists.
const membershipTagComparatorGate = "TestNothingThisPackageShipsComparesDataOutsideConstantTime"

// membershipTagCommentBlocks is every run of consecutive line comments in one file, joined.
//
// The BLOCK and not the line, because a claim runs across several lines and a name cited on one of
// them is a claim of the whole block. Read out of the file's text rather than out of go/parser's
// doc comments because this package's parse helper reads source with SkipObjectResolution and
// without ParseComments, so a declaration's Doc is nil under it.
func membershipTagCommentBlocks(t *testing.T, path string) []string {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	blocks := []string{}
	current := []string{}
	for _, line := range strings.Split(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			current = append(current, trimmed)
			continue
		}
		if len(current) != 0 {
			blocks = append(blocks, strings.Join(current, "\n"))
			current = nil
		}
	}
	if len(current) != 0 {
		blocks = append(blocks, strings.Join(current, "\n"))
	}
	return blocks
}

// TestTheMembershipTagCommentaryNamesGatesThatExistAndAClassThatHoldsItsSpellings measures the
// claims this package's prose makes about its own gates.
//
// It is here because one of them was wrong in a way no test could see. verifyMembershipTag's
// comment said "the package's derived comparator gate reads every comparison in this file's source
// and finds eighteen such names". Eighteen is the count the ./message gate reports over its own
// directory -- message/writeauth_test.go scans "." and is clean over a bytes.Equal planted in
// mls/framing_protect.go -- and the gate that does read this file derives twenty six. A number
// stated in a comment nothing recomputes is the half of a claim that goes stale in silence, so the
// number is gone and what is left is checked.
//
// Three rules, each derived. Every Test name any production comment of this package cites must be
// a test this package declares -- that rule found a second stale citation the moment it was
// written, tree.go naming a gate that had been renamed. Every comparator spelling cited by a
// comment that NAMES the comparator gate must be in the class that gate derives over this
// package's imports, and the one exempt package must be seen to be outside it. And the file that
// declares the verifier really must be one the cited gate reads, which is the half the wrong count
// was a symptom of.
func TestTheMembershipTagCommentaryNamesGatesThatExistAndAClassThatHoldsItsSpellings(t *testing.T) {
	testNames := regexp.MustCompile(`\bTest[A-Z][A-Za-z0-9_]*\b`)
	qualified := regexp.MustCompile(`\b([a-z][a-z0-9_]*)\.([A-Z][A-Za-z0-9_]*)\b`)

	declared := map[string]bool{}
	for _, path := range packageSourcePaths(t) {
		if !strings.HasSuffix(path, "_test.go") {
			continue
		}
		for _, declaration := range mustParseSource(t, path).file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if isFunction && function.Recv == nil {
				declared[function.Name.Name] = true
			}
		}
	}
	if !declared[membershipTagComparatorGate] {
		t.Fatalf("this package declares no %s, so the rules below check prose against nothing",
			membershipTagComparatorGate)
	}

	production := parsedProductionSourcesOfThisPackage(t)
	class := dataComparatorsOf(t, "this package's production source", production)
	paths := map[string]string{}
	for _, one := range importsOfSources(production) {
		paths[one.name] = one.path
	}

	cited, claiming, spellings := 0, 0, 0
	for _, path := range packageLevelFunctions(t).files {
		for _, block := range membershipTagCommentBlocks(t, path) {
			for _, name := range testNames.FindAllString(block, -1) {
				cited++
				if !declared[name] {
					t.Errorf("%s cites %s and this package declares no such test; a gate named in prose that does not exist is a claim nobody can check",
						path, name)
				}
			}
			if !strings.Contains(block, membershipTagComparatorGate) {
				continue
			}
			claiming++
			for _, spelling := range qualified.FindAllStringSubmatch(block, -1) {
				imported, isImported := paths[spelling[1]]
				if !isImported {
					// a package this source does not import is a package nothing here can call,
					// so the comment is naming it as prose rather than as a spelling of the ban
					continue
				}
				if imported == theConstantTimePackagePath {
					if slices.Contains(class, spelling[0]) {
						t.Errorf("%s names %s as the sanctioned comparison and the derived class holds it, so the gate it cites would ban the tool guardrail 8 names",
							path, spelling[0])
					}
					continue
				}
				spellings++
				if !slices.Contains(class, spelling[0]) {
					t.Errorf("%s names %s as a spelling %s catches, and the class that gate derives over this package's imports does not hold it: %v",
						path, spelling[0], membershipTagComparatorGate, class)
				}
			}
		}
	}
	if cited == 0 || claiming == 0 || spellings == 0 {
		t.Fatalf("%d test names, %d comment blocks naming %s and %d comparator spellings were read out of this package's commentary, and each of the three rules above runs over one of them",
			cited, claiming, membershipTagComparatorGate, spellings)
	}

	// and the file the claim is about really is one the cited gate reads. This is the half the
	// wrong count was a symptom of: the eighteen name gate scans ./message and never opens this
	// directory, so citing "the package's derived comparator gate" without saying which one made
	// the number wrong and the coverage unstated.
	declaring := ""
	for _, function := range packageLevelFunctions(t).functions {
		if function.name == "verifyMembershipTag" {
			declaring = function.file
		}
	}
	if declaring == "" {
		t.Fatal("this package declares no verifyMembershipTag, so the commentary this gate reads has no subject")
	}
	read := []string{}
	for _, parsed := range production {
		read = append(read, parsed.fileSet.Position(parsed.file.Pos()).Filename)
	}
	if !slices.Contains(read, declaring) {
		t.Errorf("%s declares the membership tag verifier and %s reads %v, which does not include it",
			declaring, membershipTagComparatorGate, read)
	}
	t.Logf("%d test names and %d comparator spellings were checked against %d comparators derived over this package's imports",
		cited, spellings, len(class))
}

// ---------------------------------------------------------------------------
// SealPublicMessage and OpenPublicMessage, RFC 9420 section 6.2
// ---------------------------------------------------------------------------

// framingSealed is one sealed member proposal together with everything needed to open it, built
// once per test so that each test below varies one thing rather than declaring a slightly
// different value. It is framingSigned's arrangement one layer out.
type framingSealed struct {
	crypto        CryptoProvider
	priv          SignaturePrivateKey
	pub           SignaturePublicKey
	groupContext  []byte
	membershipKey []byte
	authContent   *AuthenticatedContent
	message       *PublicMessage
}

func framingSealedMemberProposal(t *testing.T) framingSealed {
	t.Helper()
	crypto := newTestCrypto(t)
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	groupContext := framingTestGroupContext(t)
	membershipKey := bytes.Repeat([]byte{0x5a}, crypto.HashSize())
	authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPublicMessage,
		framingTestProposalContent(), groupContext)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	message, err := SealPublicMessage(crypto, membershipKey, authContent, groupContext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return framingSealed{crypto: crypto, priv: priv, pub: pub, groupContext: groupContext,
		membershipKey: membershipKey, authContent: authContent, message: message}
}

// TestPublicMessageSealOpenRoundTrip runs the whole path a peer runs: sign, seal, serialize, parse
// somebody else's octets, open.
//
// The serialization in the middle is what makes this more than a seal-then-open. Every field the
// two authenticators cover has to survive the codec for this to pass, so a codec that dropped one
// or moved one shows up here as an authentication failure rather than as a difference nothing
// compares.
//
// What it CANNOT see is stated so nobody reads it as the guard: it is a symmetry property, so an
// open that skipped either authenticator passes it, and so does a seal that took the tag under the
// wrong key -- both halves would be wrong the same way. The refusal sweeps below are what hold
// those.
func TestPublicMessageSealOpenRoundTrip(t *testing.T) {
	sealed := framingSealedMemberProposal(t)
	encoded, err := syntax.Marshal(sealed.message)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded := PublicMessage{}
	if err := syntax.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	opened, err := OpenPublicMessage(sealed.crypto, sealed.membershipKey, &decoded,
		StaticSignatureKey(sealed.pub), sealed.groupContext)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if opened.WireFormat != WireFormatPublicMessage {
		t.Errorf("opened under wire format %d, want %d", opened.WireFormat, WireFormatPublicMessage)
	}
	if opened.Content.Proposal == nil || opened.Content.Proposal.Remove == nil ||
		opened.Content.Proposal.Remove.Removed != 3 {
		t.Fatalf("opened %+v", opened.Content.Proposal)
	}
}

// TestPublicMessageRefusesApplicationContent is ValSem005, in both directions.
//
// The receive half is the one that has to exist. A sender's guard protects nobody from a peer that
// does not run this code, and the message it refuses is the user's own plaintext travelling in an
// authenticated but unencrypted frame -- so a receiver that accepted one would be handing an
// application message up to the caller having only checked that somebody signed it.
func TestPublicMessageRefusesApplicationContent(t *testing.T) {
	crypto := newTestCrypto(t)
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	groupContext := framingTestGroupContext(t)
	membershipKey := bytes.Repeat([]byte{0x5a}, crypto.HashSize())

	authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPublicMessage,
		framingTestMemberContent(), groupContext)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err = SealPublicMessage(crypto, membershipKey, authContent, groupContext); !errors.Is(err, errApplicationMustBeCiphertext) {
		t.Fatalf("seal: got %v, want errApplicationMustBeCiphertext", err)
	}

	// a hostile peer that hands us one anyway is refused on receipt, and it is refused with a
	// tag that WOULD have verified -- so what refuses it is ValSem005 and not the tag rule
	// standing in front of it.
	hostile := &PublicMessage{Content: *framingTestMemberContent(), Auth: authContent.Auth}
	tag, err := ComputeMembershipTag(crypto, membershipKey, hostile.AuthenticatedContent(), groupContext)
	if err != nil {
		t.Fatalf("the tag the hostile message carries: %v", err)
	}
	hostile.MembershipTag = tag
	_, err = OpenPublicMessage(crypto, membershipKey, hostile, StaticSignatureKey(pub), groupContext)
	if !errors.Is(err, errApplicationMustBeCiphertext) {
		t.Fatalf("open: got %v, want errApplicationMustBeCiphertext", err)
	}
}

// TestPublicMessageRefusesMissingMembershipTag is ValSem007 on the open path, over every spelling
// of an empty byte run for emptyByteSpellings' reason.
//
// It is what says the open CHECKS the tag at all for a member sender. An open that never reached
// verifyMembershipTag would answer nil here, having verified the signature of a message whose only
// statement that its sender is inside this group is absent.
func TestPublicMessageRefusesMissingMembershipTag(t *testing.T) {
	sealed := framingSealedMemberProposal(t)
	for _, empty := range emptyByteSpellings() {
		stripped := *sealed.message
		stripped.MembershipTag = empty.value
		_, err := OpenPublicMessage(sealed.crypto, sealed.membershipKey, &stripped,
			StaticSignatureKey(sealed.pub), sealed.groupContext)
		if !errors.Is(err, errMissingMembershipTag) {
			t.Errorf("a tag that is %s: got %v, want errMissingMembershipTag", empty.what, err)
		}
	}
}

// TestPublicMessageRefusesForgedMembershipTag is ValSem008 on the open path, over every flipped bit
// of the tag and every key but the right one, rather than over the one corruption somebody thought
// of.
//
// The derivation is rule 5's and this project has the measurement behind it: a tag verifier that
// read the first byte of a thirty two byte tag passed a test that flipped bit zero of byte zero,
// and a verifier that accepted every truncation passed a suite with no length case in it.
func TestPublicMessageRefusesForgedMembershipTag(t *testing.T) {
	sealed := framingSealedMemberProposal(t)
	if len(sealed.message.MembershipTag) != sealed.crypto.HashSize() {
		t.Fatalf("the sealed tag is %d bytes, want the provider's %d",
			len(sealed.message.MembershipTag), sealed.crypto.HashSize())
	}
	for at := 0; at < len(sealed.message.MembershipTag); at += 1 {
		for bit := 0; bit < 8; bit += 1 {
			tampered := *sealed.message
			tampered.MembershipTag = append([]byte(nil), sealed.message.MembershipTag...)
			tampered.MembershipTag[at] ^= 1 << uint(bit)
			_, err := OpenPublicMessage(sealed.crypto, sealed.membershipKey, &tampered,
				StaticSignatureKey(sealed.pub), sealed.groupContext)
			if !errors.Is(err, errBadMembershipTag) {
				t.Fatalf("bit %d of tag octet %d flipped: got %v, want errBadMembershipTag", bit, at, err)
			}
		}
	}
	// and every truncation and extension of it, which is the class a prefix comparison accepts
	for n := 0; n <= 2*len(sealed.message.MembershipTag); n += 1 {
		if n == len(sealed.message.MembershipTag) {
			continue
		}
		tampered := *sealed.message
		resized := make([]byte, n)
		copy(resized, sealed.message.MembershipTag)
		tampered.MembershipTag = resized
		want := errBadMembershipTag
		if n == 0 {
			want = errMissingMembershipTag
		}
		_, err := OpenPublicMessage(sealed.crypto, sealed.membershipKey, &tampered,
			StaticSignatureKey(sealed.pub), sealed.groupContext)
		if !errors.Is(err, want) {
			t.Fatalf("a %d byte tag: got %v, want %v", n, err, want)
		}
	}
	// and the tag taken under a key that is live and is not this epoch's
	wrongKey := bytes.Repeat([]byte{0x5b}, sealed.crypto.HashSize())
	_, err := OpenPublicMessage(sealed.crypto, wrongKey, sealed.message,
		StaticSignatureKey(sealed.pub), sealed.groupContext)
	if !errors.Is(err, errBadMembershipTag) {
		t.Fatalf("wrong key: got %v, want errBadMembershipTag", err)
	}
}

// TestOpenPublicMessageRefusesEveryFlippedBitOfTheSignature is ValSem010 on this path, and it is
// what says the open verifies the SIGNATURE and not only the tag.
//
// Nothing else in this file states that. The round trip is symmetric, the tag sweep above passes
// unchanged over an open that never reaches VerifyAuthenticatedContent, and the membership tag is
// taken under a key every member of the group holds -- so an open that stopped at the tag would
// accept any member's forgery of any other member's message, which is the whole distinction the
// two authenticators exist to draw.
//
// Every bit rather than one, and every length, for TestPublicMessageRefusesForgedMembershipTag's
// reason. Each row re-computes the membership tag over the tampered content, so what is being
// refused is the signature and not the tag standing in front of it.
func TestOpenPublicMessageRefusesEveryFlippedBitOfTheSignature(t *testing.T) {
	sealed := framingSealedMemberProposal(t)
	signature := sealed.message.Auth.Signature
	if len(signature) == 0 {
		t.Fatal("the sealed message carries no signature, so there is nothing here to flip")
	}
	forged := func(t *testing.T, what string, replacement []byte) {
		t.Helper()
		tampered := *sealed.message
		tampered.Auth = FramedContentAuthData{Signature: replacement}
		tag, err := ComputeMembershipTag(sealed.crypto, sealed.membershipKey,
			tampered.AuthenticatedContent(), sealed.groupContext)
		if err != nil {
			t.Fatalf("%s: the tag over the tampered message: %v", what, err)
		}
		tampered.MembershipTag = tag
		_, err = OpenPublicMessage(sealed.crypto, sealed.membershipKey, &tampered,
			StaticSignatureKey(sealed.pub), sealed.groupContext)
		if !errors.Is(err, errFramedContentBadSignature) {
			t.Fatalf("%s: got %v, want errFramedContentBadSignature", what, err)
		}
	}
	for at := 0; at < len(signature); at += 1 {
		for bit := 0; bit < 8; bit += 1 {
			flipped := append([]byte(nil), signature...)
			flipped[at] ^= 1 << uint(bit)
			forged(t, fmt.Sprintf("bit %d of signature octet %d", bit, at), flipped)
		}
	}
	for n := 0; n <= 2*len(signature); n += 1 {
		if n == len(signature) {
			continue
		}
		resized := make([]byte, n)
		copy(resized, signature)
		forged(t, fmt.Sprintf("a %d byte signature", n), resized)
	}
}

// TestOpenPublicMessageRefusesEveryKeyButTheSendersOwn sweeps the resolver's answer.
//
// A signature verification that was reached but handed the wrong key answers exactly what a
// verification that never happened answers, for a message whose signature is valid: nil. What
// separates them is a key that is not the signer's, and the class of those is every OTHER key --
// so this sweeps freshly generated pairs rather than one, and a truncated and an extended key too,
// which is the length class a verifier that compares prefixes accepts.
func TestOpenPublicMessageRefusesEveryKeyButTheSendersOwn(t *testing.T) {
	sealed := framingSealedMemberProposal(t)
	refused := 0
	for row := 0; row < 8; row += 1 {
		_, other, err := sealed.crypto.SignatureKeyPair()
		if err != nil {
			t.Fatalf("another key pair: %v", err)
		}
		if bytes.Equal(other, sealed.pub) {
			t.Fatalf("the provider answered the sender's own key at row %d", row)
		}
		_, err = OpenPublicMessage(sealed.crypto, sealed.membershipKey, sealed.message,
			StaticSignatureKey(other), sealed.groupContext)
		if !errors.Is(err, errFramedContentBadSignature) {
			t.Fatalf("row %d under another member's key: got %v, want errFramedContentBadSignature", row, err)
		}
		refused += 1
	}
	for n := 0; n <= 2*len(sealed.pub); n += 1 {
		if n == len(sealed.pub) {
			continue
		}
		resized := make([]byte, n)
		copy(resized, sealed.pub)
		_, err := OpenPublicMessage(sealed.crypto, sealed.membershipKey, sealed.message,
			StaticSignatureKey(resized), sealed.groupContext)
		if !errors.Is(err, errFramedContentBadSignature) {
			t.Fatalf("a %d byte key: got %v, want errFramedContentBadSignature", n, err)
		}
		refused += 1
	}
	if refused == 0 {
		t.Fatal("no wrong key was refused, so this observed nothing")
	}
}

// TestOpenPublicMessageAnswersItsResolversRefusalVerbatim states the other half of the resolver's
// contract.
//
// "No key could be found for this sender" is not a signature failure. It is what a receive path
// answers for a message from a leaf that has been removed or was never in the tree, there is
// nothing to verify against, and a caller has a different thing to do about it -- so it is
// answered verbatim rather than collapsed into ValSem010.
func TestOpenPublicMessageAnswersItsResolversRefusalVerbatim(t *testing.T) {
	sealed := framingSealedMemberProposal(t)
	own := errors.New("no key for that leaf")
	asked := 0
	_, err := OpenPublicMessage(sealed.crypto, sealed.membershipKey, sealed.message,
		func(sender Sender) (SignaturePublicKey, error) {
			asked += 1
			if sender.SenderType != SenderTypeMember || sender.LeafIndex != sealed.message.Content.Sender.LeafIndex {
				t.Errorf("the resolver was asked about %+v, want the message's own sender %+v",
					sender, sealed.message.Content.Sender)
			}
			return nil, own
		}, sealed.groupContext)
	if !errors.Is(err, own) {
		t.Fatalf("got %v, want the resolver's own refusal", err)
	}
	if errors.Is(err, errFramedContentBadSignature) {
		t.Error("the resolver's refusal answers to the signature refusal, so a caller cannot tell a missing key from a forgery")
	}
	if asked != 1 {
		t.Errorf("the resolver was asked %d times, want once", asked)
	}
}

// TestOpenPublicMessageRefusesAContentSignedUnderAnotherWireFormat is what the wire format is doing
// inside the section 6.1 preimage, observed at this layer.
//
// The message is a real signature over a real FramedContent, re-framed as a PublicMessage by a
// peer that has both. Its membership tag is recomputed over the PUBLIC view, so the tag verifies
// and what refuses the message is the signature -- which is the only thing left to refuse it, and
// the reason the wire format is bound into the preimage rather than merely carried beside it.
func TestOpenPublicMessageRefusesAContentSignedUnderAnotherWireFormat(t *testing.T) {
	sealed := framingSealedMemberProposal(t)
	registry := registryConstantsOfType(t, "WireFormat")
	refused := 0
	for _, name := range slices.Sorted(maps.Keys(registry)) {
		wireFormat := WireFormat(registry[name])
		if wireFormat == WireFormatPublicMessage {
			continue
		}
		elsewhere, err := SignAuthenticatedContent(sealed.crypto, sealed.priv, wireFormat,
			framingTestProposalContent(), sealed.groupContext)
		if err != nil {
			t.Fatalf("%s: sign: %v", name, err)
		}
		replayed := &PublicMessage{Content: elsewhere.Content, Auth: elsewhere.Auth}
		tag, err := ComputeMembershipTag(sealed.crypto, sealed.membershipKey,
			replayed.AuthenticatedContent(), sealed.groupContext)
		if err != nil {
			t.Fatalf("%s: the tag over the replayed message: %v", name, err)
		}
		replayed.MembershipTag = tag
		_, err = OpenPublicMessage(sealed.crypto, sealed.membershipKey, replayed,
			StaticSignatureKey(sealed.pub), sealed.groupContext)
		if !errors.Is(err, errFramedContentBadSignature) {
			t.Fatalf("%s: got %v, want errFramedContentBadSignature", name, err)
		}
		refused += 1
	}
	if refused == 0 {
		t.Fatal("no other wire format was replayed, so this observed nothing")
	}
}

// TestSealPublicMessageRefusesEveryWireFormatButItsOwn is the send side of the same binding.
//
// A caller that signed under one format and sealed under another would ship a signature that
// verifies against neither, and the failure would surface at every peer as ValSem010 rather than as
// the caller's own mistake. Refused rather than re-stamped, for framedContentTBS's reason: a
// re-stamp would sign bytes describing a message the caller did not build.
func TestSealPublicMessageRefusesEveryWireFormatButItsOwn(t *testing.T) {
	sealed := framingSealedMemberProposal(t)
	registry := registryConstantsOfType(t, "WireFormat")
	refused, accepted := 0, 0
	for _, name := range slices.Sorted(maps.Keys(registry)) {
		wireFormat := WireFormat(registry[name])
		authContent, err := SignAuthenticatedContent(sealed.crypto, sealed.priv, wireFormat,
			framingTestProposalContent(), sealed.groupContext)
		if err != nil {
			t.Fatalf("%s: sign: %v", name, err)
		}
		_, err = SealPublicMessage(sealed.crypto, sealed.membershipKey, authContent, sealed.groupContext)
		if wireFormat == WireFormatPublicMessage {
			if err != nil {
				t.Fatalf("%s: seal: %v", name, err)
			}
			accepted += 1
			continue
		}
		if !errors.Is(err, ErrWireFormatMismatch) {
			t.Fatalf("%s: got %v, want ErrWireFormatMismatch", name, err)
		}
		refused += 1
	}
	if refused == 0 || accepted != 1 {
		t.Fatalf("the sweep refused %d wire formats and accepted %d; with either half empty this states one rule rather than two",
			refused, accepted)
	}
}

// TestSealAndOpenCarryEverySenderTypeSectionSixTwoAdmits sweeps the sender type registry through
// both halves.
//
// The membership tag arm is the thing being swept. Section 6.2 gives the field to a member and to
// nobody else, because nobody else has a membership_key: an external sender has no leaf, and a new
// member has not joined. A seal that attached one anyway produces a message every other
// implementation refuses at the field after it; a seal that attached none produces a member's
// message with one of its two authenticators missing. A single-arm test is passed by both.
//
// Which sender types bind the group context comes off senderBindsGroupContext rather than off a
// list here, so the two halves cannot drift: the preimage's own rule decides what this test
// supplies.
func TestSealAndOpenCarryEverySenderTypeSectionSixTwoAdmits(t *testing.T) {
	sealed := framingSealedMemberProposal(t)
	registry := registryConstantsOfType(t, "SenderType")
	swept := 0
	for _, name := range slices.Sorted(maps.Keys(registry)) {
		senderType := SenderType(registry[name])
		binds, err := senderBindsGroupContext(senderType)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		groupContext := []byte(nil)
		if binds {
			groupContext = sealed.groupContext
		}
		content := framingTestProposalContent()
		content.Sender = *testSenderOfType(senderType)
		authContent, err := SignAuthenticatedContent(sealed.crypto, sealed.priv,
			WireFormatPublicMessage, content, groupContext)
		if err != nil {
			t.Fatalf("%s: sign: %v", name, err)
		}
		message, err := SealPublicMessage(sealed.crypto, sealed.membershipKey, authContent, groupContext)
		if err != nil {
			t.Fatalf("%s: seal: %v", name, err)
		}
		carries := senderType == SenderTypeMember
		if got := len(message.MembershipTag) != 0; got != carries {
			t.Errorf("%s: the sealed message carries a membership tag = %v, want %v", name, got, carries)
			continue
		}
		opened, err := OpenPublicMessage(sealed.crypto, sealed.membershipKey, message,
			StaticSignatureKey(sealed.pub), groupContext)
		if err != nil {
			t.Fatalf("%s: open: %v", name, err)
		}
		if opened.Content.Sender.SenderType != senderType {
			t.Errorf("%s: opened a message from sender type %d", name, opened.Content.Sender.SenderType)
			continue
		}
		swept += 1
	}
	if swept != len(registry) {
		t.Fatalf("%d of the %d sender types were carried through seal and open", swept, len(registry))
	}
}

// TestStaticSignatureKeyAnswersOneKeyForEverySender states what that resolver is and, by stating
// it, states what it must not be used for.
//
// It answers the same key whatever the sender says, which is right for the published vectors and
// for a two party test and is wrong for a group: a receive path wired to this would accept any
// member's message under any other member's leaf index. It is swept over the sender type registry
// so that "for every sender" is the class rather than the one sender somebody passed.
func TestStaticSignatureKeyAnswersOneKeyForEverySender(t *testing.T) {
	pub := SignaturePublicKey(bytes.Repeat([]byte{0x7c}, 32))
	resolve := StaticSignatureKey(pub)
	registry := registryConstantsOfType(t, "SenderType")
	for _, name := range slices.Sorted(maps.Keys(registry)) {
		answered, err := resolve(*testSenderOfType(SenderType(registry[name])))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !bytes.Equal(answered, pub) {
			t.Errorf("%s: answered %x, want %x", name, answered, pub)
		}
	}
}

// ---------------------------------------------------------------------------
// the orderings section 6.2 requires of the two doors
// ---------------------------------------------------------------------------

// framingCountingProvider counts the work each of the two authenticators asks the provider for.
//
// It is what turns an ordering claim into an observation. Every refusal below is reachable in
// more than one order and several of them answer the SAME sentinel whichever order they are
// checked in -- a corrupt tag beside a valid signature is refused as a bad tag whether the
// signature was verified first or not -- so the error alone cannot say what ran. What says it is
// the count at the moment the refusal came back: OpenPublicMessage's own comment claims a
// receiver does no public key work on behalf of any party that can reach the transport, and that
// claim is about a verification that did not happen rather than about an error.
//
// The methods are promoted from an embedded interface rather than written out, which is the
// opposite of taggingCryptoProvider's decision and is right here for the reason that one is
// right there: this wrapper counts two NAMED operations and is not a stand in for the provider,
// so a method added to the interface arriving here already implemented is exactly what should
// happen.
type framingCountingProvider struct {
	CryptoProvider
	macVerifies int
	verifies    int
}

func (self *framingCountingProvider) MacVerify(key []byte, data []byte, tag []byte) bool {
	self.macVerifies += 1
	return self.CryptoProvider.MacVerify(key, data, tag)
}

func (self *framingCountingProvider) VerifyWithLabel(pub SignaturePublicKey, label string,
	content []byte, sig []byte) error {

	self.verifies += 1
	return self.CryptoProvider.VerifyWithLabel(pub, label, content, sig)
}

// TestOpenPublicMessageRefusesInTheOrderSectionSixTwoRequires holds the two orderings
// OpenPublicMessage's documentation states as security properties.
//
// Both were prose. Measured, not supposed: with the membership tag block and the resolve-then-
// verify block exchanged -- so that a receiver does an Ed25519 verification for anybody who can
// reach the transport before asking whether the message came from inside the group at all -- the
// whole of ./mls/... and ./message/... stayed green. So did moving the ValSem005 refusal from
// ahead of both authenticators to immediately before the successful return, which is the timing
// oracle the same comment says the order exists to close.
//
// Neither reversal is visible from the error alone, which is why every row carries counts. A
// message whose tag is wrong and whose signature is wrong is refused as a bad tag in one order
// and as a bad signature in the other, so the sentinel separates those two; but a message whose
// tag is wrong and whose signature is GOOD answers the tag refusal in both orders, and what
// separates them is that one of them ran a signature verification first. The last row is the
// control and it runs the other way: with the earlier rules passing, the later checks must
// actually happen, so the zeroes above are about the order rather than about a receiver that
// verifies nothing.
func TestOpenPublicMessageRefusesInTheOrderSectionSixTwoRequires(t *testing.T) {
	sealed := framingSealedMemberProposal(t)
	forged := bytes.Clone(sealed.message.Auth.Signature)
	if len(forged) == 0 {
		t.Fatal("the sealed message carries no signature, so no row below is a message with two bad authenticators")
	}
	forged[0] ^= 0x01
	wrongTag := bytes.Repeat([]byte{0x77}, sealed.crypto.HashSize())

	// an application message a hostile peer framed in the clear, carrying authenticators that
	// are both wrong. ValSem005 needs no key to see, so nothing is spent on it.
	hostile := &PublicMessage{
		Content:       *framingTestMemberContent(),
		Auth:          FramedContentAuthData{Signature: forged},
		MembershipTag: wrongTag,
	}
	// a member's proposal whose tag is wrong and whose signature is wrong
	bothWrong := *sealed.message
	bothWrong.Auth = FramedContentAuthData{Signature: forged}
	bothWrong.MembershipTag = wrongTag
	// the same message carrying no tag at all
	tagless := bothWrong
	tagless.MembershipTag = nil
	// and one whose tag verifies over its own view and whose signature does not
	tagged := *sealed.message
	tagged.Auth = FramedContentAuthData{Signature: forged}
	honestTag, err := ComputeMembershipTag(sealed.crypto, sealed.membershipKey,
		tagged.AuthenticatedContent(), sealed.groupContext)
	if err != nil {
		t.Fatalf("the tag over the forged message: %v", err)
	}
	tagged.MembershipTag = honestTag

	for _, row := range []struct {
		what        string
		message     *PublicMessage
		want        error
		macVerifies int
		verifies    int
		resolved    int
	}{
		{what: "an application message whose tag and signature are both wrong",
			message: hostile, want: errApplicationMustBeCiphertext},
		{what: "a member's proposal whose tag and signature are both wrong",
			message: &bothWrong, want: errBadMembershipTag, macVerifies: 1},
		{what: "a member's proposal carrying no tag, whose signature is wrong",
			message: &tagless, want: errMissingMembershipTag},
		{what: "a member's proposal whose tag verifies and whose signature does not",
			message: &tagged, want: errFramedContentBadSignature, macVerifies: 1, verifies: 1, resolved: 1},
	} {
		counting := &framingCountingProvider{CryptoProvider: sealed.crypto}
		resolved := 0
		_, err := OpenPublicMessage(counting, sealed.membershipKey, row.message,
			func(sender Sender) (SignaturePublicKey, error) {
				resolved += 1
				return sealed.pub, nil
			}, sealed.groupContext)
		if !errors.Is(err, row.want) {
			t.Errorf("%s: got %v, want %v; section 6.2 refuses these in one order and this is not it",
				row.what, err, row.want)
			continue
		}
		if counting.macVerifies != row.macVerifies || counting.verifies != row.verifies || resolved != row.resolved {
			t.Errorf("%s: refused after %d mac verification(s), %d signature verification(s) and %d key resolution(s), want %d, %d and %d; a receiver that does public key work before the cheap keyless rules does it on behalf of anybody who can reach the transport",
				row.what, counting.macVerifies, counting.verifies, resolved,
				row.macVerifies, row.verifies, row.resolved)
			continue
		}
	}
}

// TestSealPublicMessageRefusesApplicationContentAheadOfEveryWireFormatMismatch is the send side's
// order, over the wire format registry rather than over the one row somebody would have written.
//
// Unlike the open's two orderings this one was claimed nowhere, which is why it could be
// exchanged with the suite green: an application message signed under a wire format that is not
// public breaks both of SealPublicMessage's message rules at once, and nothing said which answers.
// It answers ValSem005, which is the receive path's order -- a caller framing an application
// message in the clear is told the same rule by its own send path that every peer would tell it,
// rather than being sent to fix a wire format and then told about the content type on the next
// call.
//
// The second half of each row is the control that makes the first half a statement about
// PRECEDENCE. With the content type fixed at proposal the same wire formats are refused by the
// format check, so a seal that answered ValSem005 to everything would fail here.
func TestSealPublicMessageRefusesApplicationContentAheadOfEveryWireFormatMismatch(t *testing.T) {
	sealed := framingSealedMemberProposal(t)
	registry := registryConstantsOfType(t, "WireFormat")
	refused := 0
	for _, name := range slices.Sorted(maps.Keys(registry)) {
		wireFormat := WireFormat(registry[name])
		if wireFormat == WireFormatPublicMessage {
			continue
		}
		application, err := SignAuthenticatedContent(sealed.crypto, sealed.priv, wireFormat,
			framingTestMemberContent(), sealed.groupContext)
		if err != nil {
			t.Fatalf("%s: sign the application message: %v", name, err)
		}
		_, err = SealPublicMessage(sealed.crypto, sealed.membershipKey, application, sealed.groupContext)
		if !errors.Is(err, errApplicationMustBeCiphertext) {
			t.Errorf("%s: an application message signed under this wire format was refused with %v, want ValSem005; both rules refuse it and the protocol's rule is the one a peer would raise",
				name, err)
			continue
		}
		proposal, err := SignAuthenticatedContent(sealed.crypto, sealed.priv, wireFormat,
			framingTestProposalContent(), sealed.groupContext)
		if err != nil {
			t.Fatalf("%s: sign the proposal: %v", name, err)
		}
		_, err = SealPublicMessage(sealed.crypto, sealed.membershipKey, proposal, sealed.groupContext)
		if !errors.Is(err, ErrWireFormatMismatch) {
			t.Errorf("%s: a proposal signed under this wire format was refused with %v, want ErrWireFormatMismatch; without this half the row above says only that the seal refuses everything with one error",
				name, err)
			continue
		}
		refused += 1
	}
	if refused == 0 {
		t.Fatal("no wire format but the public one was swept, so this observed nothing")
	}
}

// TestSealAndOpenCarryEveryContentTypeSectionSixTwoAdmits sweeps the content type registry through
// the whole path a peer runs: sign, seal, serialize, parse somebody else's octets, open.
//
// The COMMIT row is what this exists for. Every seal and open test in this file builds its message
// out of framingTestProposalContent, and the sender type sweep beside it holds the content type
// fixed while it varies the sender -- so the confirmation_tag arm of section 6.2 was exercised on
// this path by nothing, in either half of the codec and at either door. Two independent ways of
// dropping a public commit's confirmation tag survived the whole of ./mls/... and ./message/...:
// framing the auth data under a hardcoded proposal content type in both halves of the codec, and
// a view that rebuilt the auth data with the signature alone. A public commit whose confirmation
// tag is missing from the wire and from both preimages is a commit carrying no binding to the
// transcript it confirms, and under A-ASSUME-4 the only place this code runs is interop, where
// nothing in this package is there to notice.
//
// The serialization in the middle is not decoration. It is what makes the codec part of the
// claim: a field the encoder drops is a field the membership tag no longer covers at the far end,
// so it arrives as an authentication failure rather than as a difference nothing compares.
//
// ValSem005's row is the application one, refused at the seal, which is where the registry sweep
// and the rule meet: every registered content type is carried by this path except the one the RFC
// forbids in the clear.
func TestSealAndOpenCarryEveryContentTypeSectionSixTwoAdmits(t *testing.T) {
	sealed := framingSealedMemberProposal(t)
	registry := registryConstantsOfType(t, "ContentType")
	carried, refused := 0, 0
	for _, name := range slices.Sorted(maps.Keys(registry)) {
		contentType := ContentType(registry[name])
		authContent, err := SignAuthenticatedContent(sealed.crypto, sealed.priv,
			WireFormatPublicMessage, framingTestContentOfType(t, contentType), sealed.groupContext)
		if err != nil {
			t.Fatalf("%s: sign: %v", name, err)
		}
		if contentType == ContentTypeCommit {
			// the tag is the committer's and is set after the signature, which is
			// SignAuthenticatedContent's contract: a commit's confirmation tag is a mac over a
			// transcript hash taken over this very signature, so it cannot exist until the
			// signature does.
			authContent.Auth.ConfirmationTag = bytes.Repeat([]byte{0xc7}, sealed.crypto.HashSize())
		}
		message, err := SealPublicMessage(sealed.crypto, sealed.membershipKey, authContent, sealed.groupContext)
		if contentType == ContentTypeApplication {
			if !errors.Is(err, errApplicationMustBeCiphertext) {
				t.Errorf("%s: seal: got %v, want ValSem005", name, err)
				continue
			}
			refused += 1
			continue
		}
		if err != nil {
			t.Fatalf("%s: seal: %v", name, err)
		}
		encoded, err := syntax.Marshal(message)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		decoded := PublicMessage{}
		if err := syntax.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("%s: unmarshal: %v", name, err)
		}
		opened, err := OpenPublicMessage(sealed.crypto, sealed.membershipKey, &decoded,
			StaticSignatureKey(sealed.pub), sealed.groupContext)
		if err != nil {
			t.Errorf("%s: open: %v", name, err)
			continue
		}
		if opened.Content.ContentType != contentType {
			t.Errorf("%s: opened a message of content type %d", name, opened.Content.ContentType)
			continue
		}
		if !bytes.Equal(opened.Auth.ConfirmationTag, authContent.Auth.ConfirmationTag) {
			t.Errorf("%s: opened carrying the confirmation tag %x, want the one that was sealed, %x; that tag is inside both preimages of section 6.2, so a message that arrives without it was authenticated without it at both ends",
				name, opened.Auth.ConfirmationTag, authContent.Auth.ConfirmationTag)
			continue
		}
		carried += 1
	}
	if carried == 0 || refused == 0 || carried+refused != len(registry) {
		t.Fatalf("%d of the %d registered content types were carried through seal and open and %d were refused; with either half short this states one arm rather than the rule",
			carried, len(registry), refused)
	}
}

// TestOpenPublicMessageRefusesAMembershipTagOnASenderTypeSectionSixTwoGivesNone is the arm of
// section 6.2's select that had no answer.
//
// The open read the sender type, took the no-tag branch, and left message.MembershipTag read by
// nothing and refused by nothing -- so a caller holding an external sender's message with a tag
// on it was handed back a verified object, believing two authenticators had been checked when one
// had. It is not reachable from the wire, because the codec's own select reads the field off the
// member arm alone; it is reachable from this package's callers, which is the half a codec guard
// does not cover.
//
// The refusal is stated over a tag that WOULD verify as well as over an arbitrary run of octets,
// and that row is the point: what is being refused is the presence of the field and not the value
// in it. There is no key any of these three sender types holds that a tag could have been taken
// under -- an external sender has no leaf and a new member has not joined -- so "verify it
// instead" is not an available third answer.
//
// Both controls run beside it. The same message with no tag opens, so what refused it above is
// the tag; and every spelling of an empty byte run opens too, which is emptyByteSpellings' rule
// in the direction that matters here -- a decoder hands back a non nil empty slice and a caller
// can re-slice one to nothing, and neither of those is a tag anybody attached.
func TestOpenPublicMessageRefusesAMembershipTagOnASenderTypeSectionSixTwoGivesNone(t *testing.T) {
	sealed := framingSealedMemberProposal(t)
	registry := registryConstantsOfType(t, "SenderType")
	refused, members := 0, 0
	for _, name := range slices.Sorted(maps.Keys(registry)) {
		senderType := SenderType(registry[name])
		binds, err := senderBindsGroupContext(senderType)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		groupContext := []byte(nil)
		if binds {
			groupContext = sealed.groupContext
		}
		content := framingTestProposalContent()
		content.Sender = *testSenderOfType(senderType)
		authContent, err := SignAuthenticatedContent(sealed.crypto, sealed.priv,
			WireFormatPublicMessage, content, groupContext)
		if err != nil {
			t.Fatalf("%s: sign: %v", name, err)
		}
		message, err := SealPublicMessage(sealed.crypto, sealed.membershipKey, authContent, groupContext)
		if err != nil {
			t.Fatalf("%s: seal: %v", name, err)
		}
		if senderType == SenderTypeMember {
			// the member arm is the one that REQUIRES the field, and it is checked here so that
			// this sweep cannot pass by refusing the tag everywhere.
			if len(message.MembershipTag) == 0 {
				t.Errorf("%s: the seal attached no membership tag to a member's message", name)
				continue
			}
			if _, err := OpenPublicMessage(sealed.crypto, sealed.membershipKey, message,
				StaticSignatureKey(sealed.pub), groupContext); err != nil {
				t.Errorf("%s: open: %v", name, err)
				continue
			}
			members += 1
			continue
		}
		if len(message.MembershipTag) != 0 {
			t.Errorf("%s: the seal attached a membership tag to a sender type section 6.2 gives none", name)
			continue
		}
		// the control first: with no tag this message opens, so the refusals below are about
		// the field and not about the message.
		if _, err := OpenPublicMessage(sealed.crypto, sealed.membershipKey, message,
			StaticSignatureKey(sealed.pub), groupContext); err != nil {
			t.Errorf("%s: the tagless message did not open: %v", name, err)
			continue
		}
		honest, err := ComputeMembershipTag(sealed.crypto, sealed.membershipKey,
			message.AuthenticatedContent(), groupContext)
		if err != nil {
			t.Fatalf("%s: the tag over this message's own view: %v", name, err)
		}
		for _, spelling := range []struct {
			what  string
			value []byte
		}{
			{what: "a tag this epoch's key would verify", value: honest},
			{what: "an arbitrary run of octets", value: bytes.Repeat([]byte{0x77}, sealed.crypto.HashSize())},
			{what: "a single octet", value: []byte{0x01}},
		} {
			carrying := *message
			carrying.MembershipTag = spelling.value
			_, err := OpenPublicMessage(sealed.crypto, sealed.membershipKey, &carrying,
				StaticSignatureKey(sealed.pub), groupContext)
			if !errors.Is(err, errUnexpectedMembershipTag) {
				t.Errorf("%s carrying %s: got %v, want errUnexpectedMembershipTag; a tag read by nothing is a tag the caller believes was checked",
					name, spelling.what, err)
				continue
			}
			refused += 1
		}
		for _, empty := range emptyByteSpellings() {
			carrying := *message
			carrying.MembershipTag = empty.value
			if _, err := OpenPublicMessage(sealed.crypto, sealed.membershipKey, &carrying,
				StaticSignatureKey(sealed.pub), groupContext); err != nil {
				t.Errorf("%s whose tag is %s: got %v, want the message to open; the guard is on the length, and an empty opaque<V> is not a tag anybody attached",
					name, empty.what, err)
			}
		}
	}
	if refused == 0 || members != 1 {
		t.Fatalf("%d tags were refused on sender types that carry none and %d member arms were carried; with either half empty this states one rule rather than the select",
			refused, members)
	}
}

// ---------------------------------------------------------------------------
// the sender data, RFC 9420 section 6.3.2
// ---------------------------------------------------------------------------

func TestSenderDataRoundTrip(t *testing.T) {
	senderData := SenderData{
		LeafIndex:  1,
		Generation: 7,
		ReuseGuard: [4]byte{0xde, 0xad, 0xbe, 0xef},
	}
	encoded, err := syntax.Marshal(&senderData)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// the golden is hand derived and it is what separates the field ORDER and the raw
	// reuse guard from a codec that agrees with itself: leaf_index 1 and generation 7 are
	// two different numbers, so a codec that swapped them in both halves round trips
	// perfectly and produces 00000007 00000001 here, and a reuse guard written as an
	// opaque<V> produces thirteen octets rather than twelve.
	want := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0xde, 0xad, 0xbe, 0xef}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded %x, want %x", encoded, want)
	}
	var decoded SenderData
	if err := syntax.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded != senderData {
		t.Fatalf("decoded %+v, want %+v", decoded, senderData)
	}
}

// TestCiphertextSampleIsBoundedByHashSize is the plan's regression test against the key-schedule
// plan's SenderDataKeyNonce, kept because this is the caller that ships broken if that derivation
// drifts.
//
// What it is worth on its own is less than its name claims, and that is recorded here rather than
// left for the next reader to rediscover. Its ciphertext is a run of one repeated octet, so a
// sample taken from the WRONG OFFSET reads the same bytes as one taken from the front and this
// test cannot see it; and its truncated arm is a ciphertext of exactly KDF.Nh bytes, which a rule
// that cut at Nh-1 would also cut, so a sample one octet SHORT is invisible to it too. Both were
// measured against the mutants. What it does catch is a sample longer than Nh.
// TestTheSenderDataSampleLocatesBothItsOffsetAndItsLength is the version that puts the boundary
// where the name says it is.
func TestCiphertextSampleIsBoundedByHashSize(t *testing.T) {
	crypto := newTestCrypto(t)
	secret := bytes.Repeat([]byte{0x11}, crypto.HashSize())

	long := bytes.Repeat([]byte{0xab}, crypto.HashSize()+40)
	keyLong, nonceLong, err := SenderDataKeyNonce(crypto, secret, long)
	if err != nil {
		t.Fatalf("long ciphertext: %v", err)
	}
	keyTrunc, nonceTrunc, err := SenderDataKeyNonce(crypto, secret, long[:crypto.HashSize()])
	if err != nil {
		t.Fatalf("truncated ciphertext: %v", err)
	}
	if !bytes.Equal(keyLong, keyTrunc) || !bytes.Equal(nonceLong, nonceTrunc) {
		t.Fatal("sample is not truncated to KDF.Nh")
	}

	// a ciphertext shorter than KDF.Nh must not panic and must use the whole thing
	short := []byte{0x01, 0x02, 0x03}
	keyShort, nonceShort, err := SenderDataKeyNonce(crypto, secret, short)
	if err != nil {
		t.Fatalf("short ciphertext: %v", err)
	}
	if len(keyShort) != crypto.KeySize() || len(nonceShort) != crypto.NonceSize() {
		t.Fatalf("short sample produced key %d nonce %d", len(keyShort), len(nonceShort))
	}
	keyWhole := crypto.ExpandWithLabel(secret, "key", short, crypto.KeySize())
	if !bytes.Equal(keyShort, keyWhole) {
		t.Fatal("short ciphertext sample was padded or truncated")
	}
}

// TestTheSenderDataSampleLocatesBothItsOffsetAndItsLength puts section 6.3.2's sample boundary
// where the sample rule says it is, in both directions, one octet at a time.
//
// The sweep is over a ciphertext of DISTINCT octets, which is the whole reason this test exists
// beside the one above it. A ciphertext that is a run of one value cannot separate
// ciphertext[0..Nh-1] from ciphertext[1..Nh] -- both samples read the same bytes -- so a sample
// taken from the wrong offset derives the right key from the wrong place and every whole-answer
// comparison over a repeated octet agrees with it.
//
// Every octet below KDF.Nh has to change the answer and every octet at or above it has to leave it
// alone, which locates the offset AND the length rather than inferring them from one comparison.
// Three lengths, because a rule whose bound is wrong only past 2*Nh behaves correctly at a long
// ciphertext: Nh+1 is the shortest input the cut applies to at all and is where that family is
// visible.
//
// Why the caller cares, rather than leaving this to the derivation's own plan: a sample of the
// wrong length or from the wrong offset is not a failure. It is real ciphertext, so it derives a
// well formed key of exactly the right width that opens nothing -- and against a peer that made
// the same mistake it interoperates perfectly, which is how it survives a round trip test.
func TestTheSenderDataSampleLocatesBothItsOffsetAndItsLength(t *testing.T) {
	crypto := newTestCrypto(t)
	nh := crypto.HashSize()
	secret := bytes.Repeat([]byte{0x5c}, nh)
	swept := 0
	for _, length := range []int{nh + 1, nh + nh/2, 3 * nh} {
		if length <= nh {
			t.Fatalf("a ciphertext of %d octets is not past KDF.Nh (%d), so this row observes no boundary",
				length, nh)
		}
		ciphertext := make([]byte, length)
		for i := range ciphertext {
			ciphertext[i] = byte(i%251) + 1
		}
		baseKey, baseNonce, err := SenderDataKeyNonce(crypto, secret, ciphertext)
		if err != nil {
			t.Fatalf("SenderDataKeyNonce over %d octets: %v", length, err)
		}
		inside, outside := 0, 0
		for i := range ciphertext {
			altered := bytes.Clone(ciphertext)
			altered[i] ^= 0xff
			key, nonce, err := SenderDataKeyNonce(crypto, secret, altered)
			if err != nil {
				t.Fatalf("SenderDataKeyNonce with octet %d of %d flipped: %v", i, length, err)
			}
			changed := !bytes.Equal(key, baseKey) || !bytes.Equal(nonce, baseNonce)
			if i < nh {
				if !changed {
					t.Errorf("ciphertext of %d octets: flipping octet %d changed nothing, and the sample is ciphertext[0..%d]; the sample is shorter than KDF.Nh or starts past the front",
						length, i, nh-1)
				}
				inside++
				continue
			}
			if changed {
				t.Errorf("ciphertext of %d octets: flipping octet %d changed the answer, and the sample ends at %d; the sample is longer than KDF.Nh or the cut does not fire at this length",
					length, i, nh-1)
			}
			outside++
		}
		if inside != nh || outside != length-nh {
			t.Fatalf("ciphertext of %d octets: the sweep read %d octets inside the sample and %d outside, want %d and %d",
				length, inside, outside, nh, length-nh)
		}
		swept += length
	}

	// the other end of the rule: a ciphertext shorter than KDF.Nh is used WHOLE and never
	// padded. Padding is the plausible mistake and it is a real one -- two short ciphertexts
	// differing only in length would sample identically, which is one keystream over two
	// messages, the reuse the sample exists to prevent reintroduced at the short end.
	short := bytes.Repeat([]byte{0x2a}, nh/2)
	shortKey, _, err := SenderDataKeyNonce(crypto, secret, short)
	if err != nil {
		t.Fatalf("SenderDataKeyNonce over a short ciphertext: %v", err)
	}
	padded := make([]byte, nh)
	copy(padded, short)
	paddedKey, _, err := SenderDataKeyNonce(crypto, secret, padded)
	if err != nil {
		t.Fatalf("SenderDataKeyNonce over the padded ciphertext: %v", err)
	}
	if bytes.Equal(shortKey, paddedKey) {
		t.Error("a short ciphertext derives the same key as itself zero padded to KDF.Nh, so it is being padded rather than used whole")
	}
	shorterKey, _, err := SenderDataKeyNonce(crypto, secret, short[:len(short)-1])
	if err != nil {
		t.Fatalf("SenderDataKeyNonce over a shorter ciphertext: %v", err)
	}
	if bytes.Equal(shortKey, shorterKey) {
		t.Error("two short ciphertexts of different lengths derive one key, which is one keystream over two messages")
	}
	if swept == 0 {
		t.Fatal("no ciphertext length was swept, so this gate located no boundary")
	}
}

// TestTheSenderDataKeyAndNonceAreTheWidthsTheProviderAnswers is the differential this registry
// cannot supply on its own.
//
// Both registered suites fix AEAD.Nn at 12, and the suite every other test in this file runs at
// fixes AEAD.Nk at 32 -- which is also KDF.Nh, and also the literal a body would have written
// down. So inside this registry a hardcoded 32 and a read of KeySize() are the same number and
// nothing above can separate them: measured, KeySize() replaced by 32 and NonceSize() by 12 in
// SenderDataKeyNonce leaves every other test of the section 6.3.2 path passing.
//
// The synthetic suite is the input that separates them, and the row list below is what stops the
// separation going quiet: a width here that coincided with Nk or Nn would be satisfied by the very
// literal this test exists to catch.
func TestTheSenderDataKeyAndNonceAreTheWidthsTheProviderAnswers(t *testing.T) {
	crypto := &suiteCryptoProvider{params: &ksWelcomeSyntheticParams, random: constantReader{value: 0x40}}
	for _, other := range []struct {
		name  string
		value int
	}{
		{name: "this suite's KDF.Nh", value: ksWelcomeSyntheticParams.Nh},
		{name: "the aes suite's Nk", value: 16},
		{name: "the chacha suite's Nk", value: 32},
		{name: "the registry's Nn", value: 12},
		{name: "the registry's KDF.Nh", value: newTestCrypto(t).HashSize()},
	} {
		if other.value == ksWelcomeSyntheticParams.Nk || other.value == ksWelcomeSyntheticParams.Nn {
			t.Fatalf("this suite's Nk is %d and its Nn is %d, and %s is %d; a width that coincides with either leaves the substitution it exists to catch satisfying this test",
				ksWelcomeSyntheticParams.Nk, ksWelcomeSyntheticParams.Nn, other.name, other.value)
		}
	}
	secret := bytes.Repeat([]byte{0x61}, ksWelcomeSyntheticParams.Nh)
	ciphertext := bytes.Repeat([]byte{0x62}, 4*ksWelcomeSyntheticParams.Nh)
	key, nonce, err := SenderDataKeyNonce(crypto, secret, ciphertext)
	if err != nil {
		t.Fatalf("SenderDataKeyNonce over a suite whose KDF.Nh is %d: %v", ksWelcomeSyntheticParams.Nh, err)
	}
	if len(key) != crypto.KeySize() {
		t.Errorf("the sender data key is %d octets and this suite's AEAD.Nk is %d, so the width is written down rather than read off the provider",
			len(key), crypto.KeySize())
	}
	if len(nonce) != crypto.NonceSize() {
		t.Errorf("the sender data nonce is %d octets and this suite's AEAD.Nn is %d, so the width is written down rather than read off the provider",
			len(nonce), crypto.NonceSize())
	}
	// and the values, not merely the lengths: a body that answered the right widths out of the
	// wrong expansion would satisfy everything above.
	sample := ciphertext[:crypto.HashSize()]
	if want := crypto.ExpandWithLabel(secret, "key", sample, crypto.KeySize()); !bytes.Equal(key, want) {
		t.Errorf("the sender data key is %x, want %x", key, want)
	}
	if want := crypto.ExpandWithLabel(secret, "nonce", sample, crypto.NonceSize()); !bytes.Equal(nonce, want) {
		t.Errorf("the sender data nonce is %x, want %x", nonce, want)
	}
}

// senderDataTestHeader is the cleartext PrivateMessage header the seal and open rows below run
// against. It carries authenticated_data, which the sender data AAD must NOT cover -- a header
// with that field empty cannot tell section 6.3.2's AAD from section 6.3.1's.
func senderDataTestHeader() *PrivateMessage {
	return &PrivateMessage{
		GroupId:             []byte{0x01, 0x02},
		Epoch:               9,
		ContentType:         ContentTypeApplication,
		AuthenticatedData:   []byte{0x71, 0x72, 0x73},
		EncryptedSenderData: []byte{0x81},
		Ciphertext:          []byte{0x91, 0x92},
	}
}

func TestSenderDataSealOpen(t *testing.T) {
	crypto := newTestCrypto(t)
	secret := bytes.Repeat([]byte{0x11}, crypto.HashSize())
	ciphertext := bytes.Repeat([]byte{0xab}, 64)
	header := &PrivateMessage{
		GroupId:     []byte{0x01, 0x02},
		Epoch:       9,
		ContentType: ContentTypeApplication,
	}
	senderData := SenderData{LeafIndex: 1, Generation: 7, ReuseGuard: [4]byte{1, 2, 3, 4}}

	sealed, err := sealSenderData(crypto, secret, &senderData, header, ciphertext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	opened, err := openSenderData(crypto, secret, sealed, header, ciphertext)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if *opened != senderData {
		t.Fatalf("opened %+v, want %+v", *opened, senderData)
	}

	// the epoch is in the AAD, so a rewritten header fails to open
	rewritten := *header
	rewritten.Epoch = 10
	if _, err := openSenderData(crypto, secret, sealed, &rewritten, ciphertext); !errors.Is(err, errDecryptFailed) {
		t.Fatalf("rewritten epoch: got %v, want errDecryptFailed", err)
	}

	// the ciphertext keys the sender data, so a rewritten ciphertext fails too
	other := bytes.Repeat([]byte{0xcd}, 64)
	if _, err := openSenderData(crypto, secret, sealed, header, other); !errors.Is(err, errDecryptFailed) {
		t.Fatalf("rewritten ciphertext: got %v, want errDecryptFailed", err)
	}
}

// senderDataAADParameterNames is the names of senderDataAAD's parameters, read off the source.
//
// This is what makes the sweep below a DERIVATION rather than a list. Which fields of the header
// the sender data is bound to is decided by that function's parameter list and by nothing else --
// it cannot reach a field it was not passed -- so the class of covered fields is read from there,
// and a later task that widens or narrows it moves this test with it rather than leaving a list
// behind that says what somebody once believed.
func senderDataAADParameterNames(t *testing.T) []string {
	t.Helper()
	names := []string{}
	found := false
	for file, parsed := range framingParsedProductionFiles(t) {
		for _, declaration := range parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Recv != nil || function.Name.Name != "senderDataAAD" {
				continue
			}
			if found {
				t.Fatalf("two production files declare senderDataAAD, the second being %s", file)
			}
			found = true
			for _, field := range function.Type.Params.List {
				for _, name := range field.Names {
					names = append(names, name.Name)
				}
			}
		}
	}
	if !found {
		t.Fatal("no production file of this package declares senderDataAAD, so the covered field class cannot be derived")
	}
	slices.Sort(names)
	return names
}

// TestTheSenderDataAadCoversExactlyTheHeaderFieldsItsParameterListNames sweeps EVERY field of the
// cleartext header and holds what the seal is bound to against what senderDataAAD can see.
//
// The plan's own seal test moves one field -- the epoch -- and states that one is covered. That is
// not the property. A seal built over section 6.3.1's AAD instead of section 6.3.2's is bound to
// authenticated_data as well, agrees with its own open at every input, and passes every round trip
// and every rewritten-epoch check in this file; a seal that dropped group_id from the preimage is
// invisible the same way. What separates them is the whole header, swept, against a class read off
// the source.
//
// The alteration is per TYPE rather than per field, and an unhandled type is a FAILURE rather than
// a skip, so a field added to PrivateMessage by a later task arrives here as a red test instead of
// silently leaving the sweep.
func TestTheSenderDataAadCoversExactlyTheHeaderFieldsItsParameterListNames(t *testing.T) {
	crypto := newTestCrypto(t)
	secret := bytes.Repeat([]byte{0x11}, crypto.HashSize())
	ciphertext := bytes.Repeat([]byte{0xab}, 64)
	senderData := SenderData{LeafIndex: 3, Generation: 11, ReuseGuard: [4]byte{9, 8, 7, 6}}

	header := senderDataTestHeader()
	sealed, err := sealSenderData(crypto, secret, &senderData, header, ciphertext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	covered := senderDataAADParameterNames(t)
	if len(covered) == 0 {
		t.Fatal("senderDataAAD takes no parameters, so this sweep has no class to hold the header against")
	}
	observed := []string{}
	fields := reflect.TypeOf(PrivateMessage{})
	for i := 0; i < fields.NumField(); i++ {
		name := fields.Field(i).Name
		altered := *header
		target := reflect.ValueOf(&altered).Elem().Field(i)
		switch value := target.Interface().(type) {
		case []byte:
			target.Set(reflect.ValueOf(append(bytes.Clone(value), 0x5a)))
		case uint64:
			target.Set(reflect.ValueOf(value + 1))
		case ContentType:
			// a REGISTERED neighbour, because senderDataAAD refuses an unregistered content
			// type before it writes an octet -- an unregistered one would be answered by that
			// guard rather than by the AEAD, and this row would be observing the wrong refusal.
			if value == ContentTypeApplication {
				target.Set(reflect.ValueOf(ContentTypeProposal))
			} else {
				target.Set(reflect.ValueOf(ContentTypeApplication))
			}
		default:
			t.Fatalf("PrivateMessage.%s is a %s and this sweep alters no value of that type; a header field nothing alters is a field this gate says nothing about",
				name, target.Type())
		}
		if reflect.DeepEqual(altered, *header) {
			t.Fatalf("PrivateMessage.%s was not moved by the alteration, so its row states nothing", name)
		}
		_, err := openSenderData(crypto, secret, sealed, &altered, ciphertext)
		switch {
		case err == nil:
			continue
		case errors.Is(err, errDecryptFailed):
			observed = append(observed, name)
		default:
			t.Fatalf("PrivateMessage.%s rewritten answered %v, which is neither an open nor ValSem006", name, err)
		}
	}
	slices.Sort(observed)

	want := []string{}
	for i := 0; i < fields.NumField(); i++ {
		name := fields.Field(i).Name
		if slices.Contains(covered, strings.ToLower(name[:1])+name[1:]) {
			want = append(want, name)
		}
	}
	slices.Sort(want)
	if len(want) == 0 {
		t.Fatalf("no field of PrivateMessage matched a parameter of senderDataAAD (%v), so the class reader is reading the wrong thing", covered)
	}
	if !slices.Equal(observed, want) {
		t.Errorf("rewriting %v broke the sender data open and senderDataAAD's parameters name %v; a field covered but not named is an AAD wider than section 6.3.2's, and one named but not covered is a header field the seal does not bind",
			observed, want)
	}
}

// TestTheSenderDataSealIsTheSectionSixThreeTwoConstructionAndNotOnlyItsOwnInverse recomputes the
// whole of section 6.3.2 beside the seal and compares.
//
// A seal and an open that are each other's inverse agree at every input whatever they do in
// between: the wrong label, the wrong secret, the sample taken from the wrong place, the AAD
// assembled in the wrong order -- every one of those round trips perfectly and interoperates with
// nobody. So this reads the sealed octets with the pieces the RFC names, assembled here rather
// than borrowed from the code under test, and the answer has to be the sender data's own encoding.
func TestTheSenderDataSealIsTheSectionSixThreeTwoConstructionAndNotOnlyItsOwnInverse(t *testing.T) {
	crypto := newTestCrypto(t)
	secret := bytes.Repeat([]byte{0x11}, crypto.HashSize())
	ciphertext := bytes.Repeat([]byte{0xab}, 64)
	header := senderDataTestHeader()
	senderData := SenderData{LeafIndex: 5, Generation: 2, ReuseGuard: [4]byte{0xa1, 0xa2, 0xa3, 0xa4}}

	sealed, err := sealSenderData(crypto, secret, &senderData, header, ciphertext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	sample := ciphertext[:crypto.HashSize()]
	key := crypto.ExpandWithLabel(secret, "key", sample, crypto.KeySize())
	nonce := crypto.ExpandWithLabel(secret, "nonce", sample, crypto.NonceSize())
	aad, err := senderDataAAD(header.GroupId, header.Epoch, header.ContentType)
	if err != nil {
		t.Fatalf("the section 6.3.2 aad: %v", err)
	}
	plaintext, err := crypto.AeadOpen(key, nonce, aad, sealed)
	if err != nil {
		t.Fatalf("the sealed sender data does not open under section 6.3.2's own key, nonce and aad: %v", err)
	}
	encoded, err := syntax.Marshal(&senderData)
	if err != nil {
		t.Fatalf("marshal the sender data: %v", err)
	}
	if !bytes.Equal(plaintext, encoded) {
		t.Errorf("the sealed plaintext is %x and the sender data encodes to %x", plaintext, encoded)
	}

	// and the AAD is section 6.3.2's and NOT section 6.3.1's, which is the confusion the two
	// AADs sitting next to each other invites. The content AAD is this one plus
	// authenticated_data, so a seal built over it is its own inverse and differs from this
	// only in bytes no round trip reads.
	contentAAD, err := privateContentAAD(header.GroupId, header.Epoch, header.ContentType,
		header.AuthenticatedData)
	if err != nil {
		t.Fatalf("the section 6.3.1 aad: %v", err)
	}
	if bytes.Equal(aad, contentAAD) {
		t.Fatal("the two section 6.3 aads are equal at this header, so this row cannot separate them")
	}
	if _, err := crypto.AeadOpen(key, nonce, contentAAD, sealed); err == nil {
		t.Error("the sender data opens under section 6.3.1's aad, so it was sealed under the content's associated data rather than the header's")
	}
}

// TestOpenSenderDataRefusesAPlaintextThatIsNotExactlyASenderData is the full consumption half.
//
// syntax.Unmarshal joins the decoder's answer with Done, so twelve good octets followed by a tail
// is refused. An open that reached for a bare Reader and never asked Done would accept an
// unbounded family of encodings of one header -- every one of them decrypting, decoding and
// attributing identically -- and nothing that round trips could see it, because this package would
// only ever produce the twelve octet form itself.
//
// The plaintexts are sealed with the provider directly rather than through sealSenderData, because
// sealSenderData cannot produce them: it marshals a SenderData, which is exactly twelve octets.
// That is the point -- the input this rule exists for is one a conforming sender never sends.
func TestOpenSenderDataRefusesAPlaintextThatIsNotExactlyASenderData(t *testing.T) {
	crypto := newTestCrypto(t)
	secret := bytes.Repeat([]byte{0x11}, crypto.HashSize())
	ciphertext := bytes.Repeat([]byte{0xab}, 64)
	header := senderDataTestHeader()
	senderData := SenderData{LeafIndex: 1, Generation: 7, ReuseGuard: [4]byte{1, 2, 3, 4}}
	encoded, err := syntax.Marshal(&senderData)
	if err != nil {
		t.Fatalf("marshal the sender data: %v", err)
	}

	sample := ciphertext[:crypto.HashSize()]
	key := crypto.ExpandWithLabel(secret, "key", sample, crypto.KeySize())
	nonce := crypto.ExpandWithLabel(secret, "nonce", sample, crypto.NonceSize())
	aad, err := senderDataAAD(header.GroupId, header.Epoch, header.ContentType)
	if err != nil {
		t.Fatalf("the section 6.3.2 aad: %v", err)
	}
	sealAs := func(plaintext []byte) []byte {
		t.Helper()
		blob, sealErr := crypto.AeadSeal(key, nonce, aad, plaintext)
		if sealErr != nil {
			t.Fatalf("seal %x: %v", plaintext, sealErr)
		}
		return blob
	}

	// the control: the exact encoding opens, so every refusal below is about the plaintext's
	// length and not about a key, a nonce or an aad this row got wrong.
	opened, err := openSenderData(crypto, secret, sealAs(encoded), header, ciphertext)
	if err != nil {
		t.Fatalf("the exact twelve octet encoding was refused: %v", err)
	}
	if *opened != senderData {
		t.Fatalf("opened %+v, want %+v", *opened, senderData)
	}

	for _, row := range []struct {
		what      string
		plaintext []byte
		sentinel  error
	}{
		{what: "one trailing octet", plaintext: append(bytes.Clone(encoded), 0x00), sentinel: syntax.ErrTrailingBytes},
		{what: "a whole second sender data appended", plaintext: append(bytes.Clone(encoded), encoded...), sentinel: syntax.ErrTrailingBytes},
		{what: "one octet short", plaintext: encoded[:len(encoded)-1], sentinel: syntax.ErrTruncated},
		{what: "empty", plaintext: nil, sentinel: syntax.ErrTruncated},
	} {
		got, err := openSenderData(crypto, secret, sealAs(row.plaintext), header, ciphertext)
		if !errors.Is(err, row.sentinel) {
			t.Errorf("a sender data plaintext with %s answered %v, want %v; a header this package accepts in two encodings is one a peer can rewrite without breaking",
				row.what, err, row.sentinel)
		}
		if got != nil {
			t.Errorf("a sender data plaintext with %s was refused and still answered %+v", row.what, *got)
		}
	}
}
