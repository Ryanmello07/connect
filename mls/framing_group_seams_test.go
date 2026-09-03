// The two construction-bypass seams the validation forge is built on, and the gate that keeps
// them out of everything this package ships.
//
// p8's ValSem002-011 negative tests each need a message ON THE WIRE that no correct sender would
// ever produce -- a group id from some other conversation, an epoch that has already passed, a
// stripped membership tag, non-zero padding -- while the rest of the message is this group's real
// one, sealed under this epoch's real keys, so the receiver refuses it for the rule under test
// rather than because the ciphertext was nonsense. The production Seal* entry points cannot
// express any of that, and that is the whole of their value: every authenticator they put on the
// wire is one they computed themselves.
//
// So these two are a deliberate hole in the guarantees of a package whose entire worth is that
// its guarantees hold, and the only question that matters about them is whether a shipped binary
// can reach them. IT CANNOT, and the reason is the name of this file rather than a sentence in
// it: the go tool compiles a _test.go file into `go test`'s binary and into nothing else, so a
// production file naming either seam does not build at all. "Documented as test only" would have
// been an assertion; this is the compiler.
//
// p6's plan named a NON-test file, framing_group_seams.go, and would have excused the
// uncalled-declaration failure that follows with a packageDeclarationsAwaitingTheirFirstCaller
// entry. Both halves of that are refused here. Compiled into the package proper, the seams ship
// in every binary that imports mls; and the excuse table's entire safety argument is expiry by
// failure -- an entry dies on the commit that gives its declaration a production caller -- so an
// entry for a seam is the one entry that can never expire, which is what
// TestNoExcuseAwaitingAFirstCallerNamesAnExpiryThatCannotArrive already refuses. Task 11's count
// form of the section 6.3.1 serializer went into framing_protect_test.go for exactly this reason,
// and these go here for it.
//
// The gate at the foot of this file is the half the compiler does not hold. The compiler says
// production cannot call a declaration of the test binary; nothing said these declarations STAY
// in the test binary, and moving both into framing_group_seams.go together WITH a production
// caller passes every other gate this package has -- measured, not assumed. The class it reads is
// derived from what a construction bypass DOES rather than from these two names.
package mls

import (
	"bytes"
	"errors"
	"go/ast"
	"slices"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// the seams
// ---------------------------------------------------------------------------

// sealFramedContentForTest seals a caller-assembled FramedContent under this group's real epoch
// keys, with the caller's own FramedContentAuthData in place of the authenticators a correct
// sender would have computed.
//
// It is the zero-padding entry point and it delegates, so there is one copy of the forge rather
// than two that agree until the day one of them changes.
func (self *Group) sealFramedContentForTest(c *FramedContent, auth *FramedContentAuthData,
	wf WireFormat, signer SignaturePrivateKey) ([]byte, error) {

	return self.sealFramedContentWithPaddingForTest(c, auth, wf, signer, nil)
}

// sealFramedContentWithPaddingForTest is the same seal with caller-supplied padding octets, which
// is the shape ValSem011 needs: PaddingSizeV1 is 0 and the exported SealPrivateMessage takes a
// paddingSize int, so a NON-zero padding tail is expressible through the unexported
// sealPrivateMessage and through nothing else this package offers.
//
// The answer is a whole encoded MLSMessage, through the same MarshalMLSMessage every sender
// leaves by, so the forge hands the receiver exactly what the network would rather than a struct
// the receive path never had to parse.
//
// Only the SENDER-CHOSEN fields are the caller's. The group context, the membership key, the
// sender data secret and the secret tree are this group's own, which is why these are methods on
// *Group at all: a forge holding its own keys would produce a message the receiver refuses at the
// first AEAD open, and a negative test that fails for two reasons at once establishes neither.
//
// No stateLock is taken, and that is a decision rather than an omission. GroupContext takes it
// and sync.Mutex is not reentrant, so a seam that locked around this call would deadlock on its
// first use; a Group is documented as unsafe for concurrent use and the forge drives one from a
// single test goroutine. It does CONSUME a generation of the sender's ratchet, exactly as a real
// send does, because the message is meant to be indistinguishable from one.
func (self *Group) sealFramedContentWithPaddingForTest(c *FramedContent, auth *FramedContentAuthData,
	wf WireFormat, signer SignaturePrivateKey, padding []byte) ([]byte, error) {

	groupContext, err := self.GroupContext()
	if err != nil {
		return nil, err
	}
	// signed NORMALLY first, so the signature is over the caller's own content and the forge is
	// confined to the auth data. The alternative -- assembling an AuthenticatedContent by hand --
	// would put a message on the wire failing the signature check as well as the rule under test.
	authContent, err := SignAuthenticatedContent(self.crypto, signer, wf, c, groupContext)
	if err != nil {
		return nil, err
	}
	// nil leaves the honest signature standing, which is what the ValSem002-004 tests want: those
	// forge the CONTENT and need the authenticators to be real, so the refusal is the group id or
	// the epoch and not a signature nobody wrote.
	if auth != nil {
		authContent.Auth = *auth
	}

	// the field is spelled schedule. p6's plan wrote self.keySchedule against a p7 draft that
	// never landed under that name, and p7 owns this struct.
	secrets := self.schedule.Secrets()
	message := &MLSMessage{Version: ProtocolVersionMls10, WireFormat: wf}
	switch wf {
	case WireFormatPublicMessage:
		publicMessage, err := SealPublicMessage(self.crypto, secrets.Membership, authContent,
			groupContext)
		if err != nil {
			return nil, err
		}
		message.PublicMessage = publicMessage
	case WireFormatPrivateMessage:
		privateMessage, err := sealPrivateMessage(self.crypto, self.secretTree, secrets.SenderData,
			authContent, padding)
		if err != nil {
			return nil, err
		}
		message.PrivateMessage = privateMessage
	default:
		return nil, ErrWireFormatMismatch
	}
	return MarshalMLSMessage(message)
}

// ---------------------------------------------------------------------------
// what the seams actually put on the wire
// ---------------------------------------------------------------------------

// seamSealPrivate seals one private message through the padding seam and hands back the arm a
// receiver would be given, so the three padding cases below differ in the padding and in nothing
// else.
func seamSealPrivate(t *testing.T, group *Group, content *FramedContent, owner *testMember,
	padding []byte) *PrivateMessage {

	t.Helper()
	encoded, err := group.sealFramedContentWithPaddingForTest(content, nil, WireFormatPrivateMessage,
		owner.SigPriv, padding)
	if err != nil {
		t.Fatalf("seal a private message with %d octets of padding: %v", len(padding), err)
	}
	message, err := ParseMLSMessage(encoded)
	if err != nil {
		t.Fatalf("the seam's octets do not parse as an MLSMessage: %v", err)
	}
	if message.WireFormat != WireFormatPrivateMessage || message.PrivateMessage == nil {
		t.Fatalf("the seam answered wire format %d with private arm %v, want a PrivateMessage",
			message.WireFormat, message.PrivateMessage)
	}
	return message.PrivateMessage
}

// TestTheConstructionBypassSeamsPutTheGroupsOwnMessageOnTheWire is the seams' own contract, and
// it is deliberately NOT a second copy of p8's ValSem catalogue.
//
// p6's plan says to write no test here, on the grounds that two tests over one seam drift into
// disagreeing about which fields the caller controls. For the TEN RULES that is right: each of
// them is a statement about the receive path and each of them is p8's. What the reasoning does
// not cover is the seam itself, and the gap is the shape this project keeps paying for. Every one
// of those ten tests reads a refusal, so a seam that sealed under the wrong epoch secret, dropped
// the padding it was handed, or ignored the auth data entirely still produces a refusal at every
// one of them: ten green tests over a forge that forges nothing.
//
// So what is asserted here is the property that has to hold before any of those ten mean
// anything, and nothing beyond it. With NOTHING forged the seam produces a message this group's
// own receive path ACCEPTS; and each of the three things a caller controls -- the content, the
// auth data, the padding -- is observed on the wire rather than assumed to have reached it.
func TestTheConstructionBypassSeamsPutTheGroupsOwnMessageOnTheWire(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "seam-group")
	defer group.Close()

	groupContext, err := group.GroupContext()
	if err != nil {
		t.Fatalf("GroupContext: %v", err)
	}
	context := testGroupContextOf(t, group)
	// a PROPOSAL and not application data, because ValSem005 refuses application content in a
	// PublicMessage on the send path as well as on the receive one; one content type is what lets
	// both arms below carry the same message.
	content := &FramedContent{
		GroupId:           context.GroupId,
		Epoch:             context.Epoch,
		Sender:            Sender{SenderType: SenderTypeMember, LeafIndex: group.OwnLeafIndex()},
		AuthenticatedData: []byte{0x09},
		ContentType:       ContentTypeProposal,
		Proposal:          &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 3}},
	}
	resolve := StaticSignatureKey(owner.SigPub)
	secrets := group.schedule.Secrets()

	// the public arm with nothing forged: this epoch's membership tag, the owner's signature, and
	// the receive path a peer would run.
	encoded, err := group.sealFramedContentForTest(content, nil, WireFormatPublicMessage,
		owner.SigPriv)
	if err != nil {
		t.Fatalf("seal a public message through the seam: %v", err)
	}
	message, err := ParseMLSMessage(encoded)
	if err != nil {
		t.Fatalf("the seam's octets do not parse as an MLSMessage: %v", err)
	}
	if message.WireFormat != WireFormatPublicMessage || message.PublicMessage == nil {
		t.Fatalf("the seam answered wire format %d with public arm %v, want a PublicMessage",
			message.WireFormat, message.PublicMessage)
	}
	opened, err := OpenPublicMessage(crypto, secrets.Membership, message.PublicMessage, resolve,
		groupContext)
	if err != nil {
		t.Fatalf("this group's own receive path refuses the seam's UNFORGED message: %v; a forge whose honest output is already refused says nothing about the rule a negative test is aiming at",
			err)
	}
	if opened.Content.ContentType != ContentTypeProposal ||
		opened.Content.Sender.LeafIndex != group.OwnLeafIndex() ||
		!bytes.Equal(opened.Content.AuthenticatedData, content.AuthenticatedData) ||
		!bytes.Equal(opened.Content.GroupId, content.GroupId) {

		t.Errorf("the message that came back carries %+v and the caller assembled %+v; the seam is not sending the content it was handed",
			opened.Content, *content)
	}

	// and the auth data really is the caller's. A signature over nothing, carried through the
	// seal and refused by the SIGNATURE check -- the membership tag verifies, because the seam
	// MACs what it is about to send rather than what it signed, which is what makes a forged
	// signature reach the receiver's signature check at all.
	forged := &FramedContentAuthData{
		Signature: bytes.Repeat([]byte{0xaa}, len(opened.Auth.Signature))}
	encoded, err = group.sealFramedContentForTest(content, forged, WireFormatPublicMessage,
		owner.SigPriv)
	if err != nil {
		t.Fatalf("seal a forged public message through the seam: %v", err)
	}
	message, err = ParseMLSMessage(encoded)
	if err != nil {
		t.Fatalf("the forged message does not parse: %v", err)
	}
	if !bytes.Equal(message.PublicMessage.Auth.Signature, forged.Signature) {
		t.Fatalf("the seam put %x on the wire and the caller's auth data carried %x; nothing p8 forges through the auth argument would reach a receiver",
			message.PublicMessage.Auth.Signature, forged.Signature)
	}
	if _, err := OpenPublicMessage(crypto, secrets.Membership, message.PublicMessage, resolve,
		groupContext); err == nil {
		t.Errorf("the receive path accepted a message carrying a signature over nothing")
	}

	// the private arm, opened on a RECEIVER's own ratchet at this epoch rather than on the
	// sender's: the seal consumes the generation it sealed under, exactly as a real send does, so
	// the sending group cannot also be the receiving one.
	receiver, err := NewSecretTree(crypto, group.tree.LeafWidth(), secrets.Encryption)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	unpadded := seamSealPrivate(t, group, content, owner, nil)
	padded := seamSealPrivate(t, group, content, owner, make([]byte, seamPaddingOctets))
	nonZero := seamSealPrivate(t, group, content, owner,
		bytes.Repeat([]byte{0x01}, seamPaddingOctets))

	if grew := len(padded.Ciphertext) - len(unpadded.Ciphertext); grew != seamPaddingOctets {
		t.Errorf("%d octets of padding grew the ciphertext by %d; the padding the caller hands the seam is not reaching the wire, and ValSem011 has nothing to be a rule about",
			seamPaddingOctets, grew)
	}
	// in generation order, because that is the order they were sealed in and one receiver ratchet
	// walks forward through them the way a real one does.
	if _, err := OpenPrivateMessage(crypto, receiver, secrets.SenderData, unpadded, resolve,
		groupContext); err != nil {

		t.Fatalf("this group's own receive path refuses the seam's UNFORGED private message: %v", err)
	}
	if _, err := OpenPrivateMessage(crypto, receiver, secrets.SenderData, padded, resolve,
		groupContext); err != nil {

		t.Fatalf("the receive path refuses an all zero padded message the seam produced: %v", err)
	}
	if _, err := OpenPrivateMessage(crypto, receiver, secrets.SenderData, nonZero, resolve,
		groupContext); !errors.Is(err, errNonZeroPadding) {

		t.Errorf("a non zero padding tail was answered %v, want errNonZeroPadding; ValSem011 is the one rule in the catalogue this package can produce a case for through nothing but this seam",
			err)
	}

	// the wire format the seams refuse. Welcome is a REGISTERED format that carries no framed
	// content, so it reaches the select rather than being turned away by the signature preimage,
	// which is what makes this the default arm's own refusal and not some earlier one.
	if _, err := group.sealFramedContentForTest(content, nil, WireFormatWelcome,
		owner.SigPriv); !errors.Is(err, ErrWireFormatMismatch) {

		t.Errorf("sealing under a wire format that frames no content answered %v, want ErrWireFormatMismatch",
			err)
	}
}

// seamPaddingOctets is the padding tail the two cases above differ by. Wide enough that a
// ciphertext growing by it is not a length this codec could have produced by accident.
const seamPaddingOctets = 32

// ---------------------------------------------------------------------------
// and they stay in the test binary
// ---------------------------------------------------------------------------

// The door every octet this package sends leaves through, the type it leaves as, and the
// authenticators a correct assembly computes for itself.
//
// These are the gate's ANCHORS and not its class. What rule 5 refuses is a class written out as a
// list of its members, which is how a hand written roster comes to understate the thing it
// guards; a derivation still has to start from something the package declares, and each of these
// three is checked below against the package's own declarations, so a rename that moved one fails
// here rather than quietly emptying the rule.
const (
	seamWireDoor             = "MarshalMLSMessage"
	seamWireDoorType         = "MLSMessage"
	seamForgedAuthenticators = "FramedContentAuthData"
)

// One declaration of this package, as this gate reads it.
type seamCandidate struct {
	// Type.Method for a method and the bare name otherwise, which is how a report names it.
	name string
	// the method or function name alone, which is how ANOTHER body names it. A method is reached
	// through a selector whose tail carries no receiver, so the reachability walk below is keyed
	// on this and the report on the name above.
	bare string
	file string
	// a PARAMETER hands it the authenticators, so its caller chose what the receiver will check.
	forgeable bool
	// every identifier its body names.
	names map[string]bool
}

// seamCandidatesIn reads one set of parsed files into the shape the two rules below ask about.
//
// Parameters and not the receiver. A method whose RECEIVER is the authenticators is a codec of
// them -- (*FramedContentAuthData).MarshalMLS is one -- and banning that shape would ban the
// encoder every honest sender runs. What makes a declaration a bypass is being HANDED
// authenticators for a message it is assembling on somebody else's behalf.
func seamCandidatesIn(parsed []parsedSource) []seamCandidate {
	candidates := []seamCandidate{}
	for _, source := range parsed {
		for _, declaration := range source.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			candidate := seamCandidate{
				name:  function.Name.Name,
				bare:  function.Name.Name,
				file:  source.fileSet.Position(function.Pos()).Filename,
				names: map[string]bool{},
			}
			if function.Recv != nil && len(function.Recv.List) == 1 {
				candidate.name = receiverTypeName(function.Recv.List[0].Type) + "." + candidate.bare
			}
			for _, field := range function.Type.Params.List {
				ast.Inspect(field.Type, func(node ast.Node) bool {
					if identifier, isIdentifier := node.(*ast.Ident); isIdentifier &&
						identifier.Name == seamForgedAuthenticators {
						candidate.forgeable = true
					}
					return true
				})
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				if identifier, isIdentifier := node.(*ast.Ident); isIdentifier {
					candidate.names[identifier.Name] = true
				}
				return true
			})
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

// seamsReachingTheWireDoor answers which declarations put octets on the wire, DIRECTLY or through
// another declaration of the package that does.
//
// Transitive rather than one hop, because the pair this file declares is a wrapper and a body:
// the wrapper names no MLSMessage at all, and a rule reading one hop would report the seam that
// does the work and call the seam beside it clean. It is a fixed point over bare names, so two
// declarations sharing one spelling merge -- which errs towards calling a declaration a seam,
// the direction a gate is allowed to err in.
func seamsReachingTheWireDoor(candidates []seamCandidate) map[string]bool {
	reaches := map[string]bool{}
	for grew := true; grew; {
		grew = false
		for _, candidate := range candidates {
			if reaches[candidate.bare] {
				continue
			}
			if candidate.names[seamWireDoor] || candidate.names[seamWireDoorType] {
				reaches[candidate.bare] = true
				grew = true
				continue
			}
			for named := range candidate.names {
				if reaches[named] {
					reaches[candidate.bare] = true
					grew = true
					break
				}
			}
		}
	}
	return reaches
}

// constructionBypassSeamsIn is the class: a declaration handed the authenticators by its caller
// that reaches the wire door with them.
//
// The honest limit, recorded because a gate nobody knows the edge of is worse than none. A seam
// that answered a *PrivateMessage instead of encoded octets never names the wire door and is
// outside this reading, as is one that took its forged tag as a bare []byte rather than as the
// structure that carries it. Both are further from the shape the validation forge asked for than
// the plan's own draft was, and neither is what this gate was measured against: what it is
// measured against is the plan's file, moved into the package proper with a caller.
func constructionBypassSeamsIn(parsed []parsedSource) []seamCandidate {
	candidates := seamCandidatesIn(parsed)
	reaches := seamsReachingTheWireDoor(candidates)
	seams := []seamCandidate{}
	for _, candidate := range candidates {
		if candidate.forgeable && reaches[candidate.bare] {
			seams = append(seams, candidate)
		}
	}
	slices.SortFunc(seams, func(a seamCandidate, b seamCandidate) int {
		return strings.Compare(a.name, b.name)
	})
	return seams
}

// seamNamesOf is what the assertions compare, so a report and a comparison cannot spell the same
// declaration two ways.
func seamNamesOf(seams []seamCandidate) []string {
	names := []string{}
	for _, seam := range seams {
		names = append(names, seam.name)
	}
	return names
}

// A package holding one of each shape, so a matcher that stopped matching fails here rather than
// reporting this package clean.
//
// Four negatives and three positives, and every negative is a shape this package's PRODUCTION
// source actually has: a fragment serializer handed the authenticators
// (marshalPrivateMessageContentWithPadding), a sender that computes its own and names the type in
// its body (SignAuthenticatedContent), and a codec whose receiver is the authenticators
// ((*FramedContentAuthData).MarshalMLS). A rule that swept any of them in would ban the send path
// rather than the forge.
const constructionBypassSeamControl = `package control

// the seam shape: the caller chooses the authenticators and the answer is what the wire carries.
func forgesTheAuthenticatorsOntoTheWire(auth *FramedContentAuthData) ([]byte, error) {
	message := &MLSMessage{}
	return MarshalMLSMessage(message)
}

// the same, one call away. Without this half the rule reads the body of a two declaration seam
// and reports the wrapper beside it clean.
func forgesThroughAWrapper(auth *FramedContentAuthData) ([]byte, error) {
	return forgesTheAuthenticatorsOntoTheWire(auth)
}

// a METHOD with the seam shape. Both real seams are methods on *Group, so a matcher reading only
// free functions would report this package clean while shipping them.
func (self *Group) forgesAsAMethod(auth *FramedContentAuthData) ([]byte, error) {
	return MarshalMLSMessage(&MLSMessage{})
}

// handed the authenticators and serializing a FRAGMENT, which is
// marshalPrivateMessageContentWithPadding's shape and production's own.
func serializesAFragment(auth *FramedContentAuthData) ([]byte, error) {
	return auth.Signature, nil
}

// reaching the wire door while computing its own authenticators, which is every honest sender.
// The type is named in the BODY, so this is what says the rule reads parameters and not mentions.
func sealsWhatItSignedItself(signer SignaturePrivateKey) ([]byte, error) {
	auth := FramedContentAuthData{Signature: signer}
	_ = auth
	return MarshalMLSMessage(&MLSMessage{})
}

// the codec OF the authenticators, reaching the wire door with them as its RECEIVER. It is what
// says the rule reads parameters and not receivers.
func (self *FramedContentAuthData) marshalsAMessage(message *MLSMessage) error {
	_, err := MarshalMLSMessage(message)
	return err
}

// naming neither the door nor the authenticators, so the fixed point has something to leave out.
func touchesNeither(count int) int {
	return count + 1
}
`

// TestTheConstructionBypassSeamGateReadsItsControl runs the matcher on a package known to hold
// every shape it must separate, so a rule narrowed by an edit fails here rather than reporting
// the real package clean -- which is the one outcome a gate must never produce by accident.
func TestTheConstructionBypassSeamGateReadsItsControl(t *testing.T) {
	seams := constructionBypassSeamsIn([]parsedSource{
		mustParseText(t, "seam_control.go", constructionBypassSeamControl)})
	want := []string{
		"Group.forgesAsAMethod",
		"forgesTheAuthenticatorsOntoTheWire",
		"forgesThroughAWrapper",
	}
	if !slices.Equal(seamNamesOf(seams), want) {
		t.Fatalf("the matcher read %v out of the control, want %v; a positive it misses is a seam it would ship and a negative it sweeps in is the send path",
			seamNamesOf(seams), want)
	}
}

// TestEveryConstructionBypassSeamIsDeclaredInTestSource is the statement the compiler cannot
// make on its own.
//
// The compiler holds one direction already and holds it absolutely: production source naming an
// unexported declaration of a _test.go file does not build. What it does not hold is the seams
// STAYING there. Moving both into framing_group_seams.go the way p6's plan wrote it, with a
// production caller so nothing reads as uncalled, satisfies every other gate in this package --
// measured against TestNoStubShapesRemainInSource, which reports an uncalled declaration and has
// nothing to say about a called one.
//
// So the class is derived from what a construction bypass DOES: it is handed the authenticators a
// correct assembly would have computed, and it reaches the door this package's octets leave by. A
// seam written tomorrow under any spelling, in any file, in either of those two shapes, is in it.
func TestEveryConstructionBypassSeamIsDeclaredInTestSource(t *testing.T) {
	parsed := []parsedSource{}
	for _, path := range packageSourcePaths(t) {
		parsed = append(parsed, mustParseSource(t, path))
	}

	// the anchors, against the package's own declarations. A door that had been renamed leaves
	// the reachability half matching nothing, and a class of nothing reports exactly what a clean
	// package reports.
	declared := packageLevelDeclarations(t, ".")
	for _, anchor := range []string{seamWireDoor, seamWireDoorType, seamForgedAuthenticators} {
		file, isDeclared := declared[anchor]
		if !isDeclared {
			t.Fatalf("this package declares no %s, so the rule below is anchored on a name that has moved and reads nothing",
				anchor)
		}
		if strings.HasSuffix(file, "_test.go") {
			t.Fatalf("%s is declared in %s; the anchors are production's own, and one that had become the test binary's would make every seam its own excuse",
				anchor, file)
		}
	}

	candidates := seamCandidatesIn(parsed)
	// the near miss, pinned in both directions the way errNilLeafOccupancyTest is. It is
	// production source, it IS handed the authenticators, and it serializes a fragment rather
	// than reaching the wire -- so it is what says the parameter half of the rule reads real
	// source, and if it ever reached the door this package would hold a production forge.
	nearMiss := "marshalPrivateMessageContentWithPadding"
	held := false
	for _, candidate := range candidates {
		if candidate.name != nearMiss {
			continue
		}
		held = true
		if !candidate.forgeable {
			t.Errorf("%s is not read as handed the authenticators, and it takes an *%s; the parameter half of this rule is matching nothing in real source",
				nearMiss, seamForgedAuthenticators)
		}
		if strings.HasSuffix(candidate.file, "_test.go") {
			t.Errorf("%s has moved into the test binary (%s), so the near miss this rule is measured against is no longer production's own",
				nearMiss, candidate.file)
		}
	}
	if !held {
		t.Fatalf("the scan read no declaration of %s, so it is not reading this package's production source at all",
			nearMiss)
	}

	seams := constructionBypassSeamsIn(parsed)
	if len(seams) == 0 {
		t.Fatalf("the class is empty, and this file declares two of it; the rule is reading nothing rather than finding nothing")
	}
	shipped := []string{}
	for _, seam := range seams {
		if !strings.HasSuffix(seam.file, "_test.go") {
			shipped = append(shipped, seam.name+" ("+seam.file+")")
		}
	}
	if len(shipped) != 0 {
		t.Errorf("%v are handed their authenticators and reach %s from source the go tool compiles into every binary that imports this package; a construction bypass belongs in a _test.go file, where the compiler and not a comment is what keeps production out of it",
			shipped, seamWireDoor)
	}
	t.Logf("%d construction bypass seam(s), every one of them declared in test source: %v",
		len(seams), seamNamesOf(seams))
}
