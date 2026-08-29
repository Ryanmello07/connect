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
	"maps"
	"reflect"
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
		t.Fatal("no registered sender type produced a row, so this half of the gate runs over the empty set")
	}
	unknownSender := framingTestProposalContent()
	unknownSender.Sender = Sender{SenderType: SenderType(framingUnregisteredCodePoint(t, "SenderType", 0xff))}
	structural["a sender type no registry holds"] =
		framingPreimageInput{WireFormatPublicMessage, unknownSender, framingTestGroupContext(t)}
	structural["a wire format no registry holds"] = framingPreimageInput{
		WireFormat(framingUnregisteredCodePoint(t, "WireFormat", 0xffff)),
		framingTestMemberContent(), framingTestGroupContext(t)}

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
