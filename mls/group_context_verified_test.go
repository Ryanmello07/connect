// The gates over VerifiedGroupContext, and the one question about it that IS a property of
// source shape.
//
// WHAT THIS FILE IS INSTEAD OF. proposal_binding_test.go used to carry a second gate: an AST walk
// over every call of a binding writer, refusing an argument whose chain of selections reached a
// type this package decodes off the wire. It was written three times and bypassed three times --
// by any *GroupContext at all, then by one local struct between the decode and the bind, then
// twice over by an ordinary accessor method and by an embedded wire type whose promoted selection
// the walk never consulted the type checker about. All three bypasses are now compile errors,
// because NewProposalCache and Rebind take a *VerifiedGroupContext and none of those shapes
// produces one.
//
// THE DIFFERENCE BETWEEN THE QUESTION THAT FAILED AND THE ONE HELD HERE is worth stating, because
// this file is an AST gate too and a reader is entitled to ask what makes it different. The
// deleted gate asked WHERE A VALUE CAME FROM, which is a fact about a computation and not about
// the text: the same expression -- a field selected out of a struct -- is the defect when the
// struct was decoded and the remedy when it was the group's own state, and no amount of walking
// separates them. This one asks WHICH DECLARATIONS BUILD A NAMED STRUCT TYPE, which is a closed
// syntactic question: Go has exactly two ways to put a value in a field, a composite literal and
// an assignment, and the type checker resolves both by object. There is no third spelling to be
// bypassed by, and the compiler already refuses every declaration outside this package because
// the field is unexported.
//
// SO THE SCOPE IS THIS PACKAGE AND THAT IS A COMPILER FACT rather than a choice, exactly as it is
// for the cache's own binding: the gate asserts the field really is unexported instead of leaving
// that as the unstated reason a narrow scan is enough.
package mls

import (
	"bytes"
	"errors"
	"go/ast"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The two names this file's derivation is written against, checked against the compiler's reading
// below rather than trusted: a rename that left these behind would empty the class, and an empty
// class is what a package that builds no verified context and a broken matcher both look like.
const (
	verifiedGroupContextTypeName  = "VerifiedGroupContext"
	verifiedGroupContextFieldName = "inner"
)

// verifiedGroupContextConstruction is one build of the type: where it is and how it is spelled.
type verifiedGroupContextConstruction struct {
	where string
	how   string
}

// verifiedGroupContextConstructionsIn is the class: every declaration of one checked package that
// builds a VerifiedGroupContext carrying a context, with the count of nodes it judged at all.
//
// TWO WAYS A FIELD IS FILLED AND THERE IS NO THIRD. A composite literal is how the constructor
// writes it, and an assignment to the field is the other; a matcher reading only one of them would
// report a clean run over a package that used the other, which is the half this gate exists to
// hold. Both arms go through the type checker rather than through the spelling, so a literal
// written with the type elided inside a slice of them is a member, and a local named
// VerifiedGroupContext in some other package is not.
//
// AN EMPTY LITERAL IS NOT A MEMBER, and that is deliberate rather than an omission.
// VerifiedGroupContext{} carries a nil context, which is the zero value every door of this package
// already refuses with ErrNilGroupContext -- it confers no authority on anything, so counting it
// would make the class about a shape rather than about the thing the class is for. Another package
// can spell that literal too and no gate here could reach it; what makes that safe is the refusal
// and not this scan.
//
// The judged count is carried for the reason every derived gate of this package carries one: a
// matcher that stopped resolving its subject reports an EMPTY class, and an empty class is exactly
// what a package that builds none reports.
func verifiedGroupContextConstructionsIn(checked checkedBodies) (map[string][]verifiedGroupContextConstruction, int) {
	found := map[string][]verifiedGroupContextConstruction{}
	judged := 0
	for _, file := range checked.files {
		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			name := extensionTypeSelectionDeclarationName(checked, function)
			record := func(node ast.Node) {
				found[name] = append(found[name], verifiedGroupContextConstruction{
					where: checked.where(node),
					how:   checked.render(node),
				})
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch built := node.(type) {
				case *ast.CompositeLit:
					if !extensionTypeSelectionNamedAs(checked.info.TypeOf(built),
						verifiedGroupContextTypeName) {
						return true
					}
					judged += 1
					if len(built.Elts) == 0 {
						return true
					}
					record(built)
				case *ast.AssignStmt:
					for _, target := range built.Lhs {
						selector, isSelector := extensionTypeSelectionUnparenthesised(
							target).(*ast.SelectorExpr)
						if !isSelector || selector.Sel.Name != verifiedGroupContextFieldName {
							continue
						}
						if !extensionTypeSelectionNamedAs(checked.info.TypeOf(selector.X),
							verifiedGroupContextTypeName) {
							continue
						}
						judged += 1
						record(built)
					}
				}
				return true
			})
		}
	}
	return found, judged
}

// verifiedGroupContextControl is a package the matcher has never seen, carrying every shape this
// rule has an answer for.
//
// A control rather than a second opinion about the real source: a matcher that resolved nothing
// reports a clean run over mls too, and the only way to tell that apart from a package that obeys
// the rule is to run it over source known to hold both answers.
const verifiedGroupContextControl = `package control

type GroupContext struct {
	GroupId []byte
	Epoch   uint64
}

type VerifiedGroupContext struct {
	inner *GroupContext
}

// a type with a field of the same name, so the rule is about the TYPE the field belongs to and
// not about the word
type somethingElse struct {
	inner *GroupContext
}

// the shape the real constructor is written in
func confirmIt(context *GroupContext) *VerifiedGroupContext {
	return &VerifiedGroupContext{inner: context}
}

// the same build with the field name left off, which a matcher reading only keyed elements walks
// straight past
func confirmItPositionally(context *GroupContext) *VerifiedGroupContext {
	return &VerifiedGroupContext{context}
}

// and the same build written as an assignment, which is the other of the two ways Go fills a field
func fillItAfterwards(context *GroupContext) *VerifiedGroupContext {
	built := &VerifiedGroupContext{}
	built.inner = context
	return built
}

// a literal with the type elided inside a slice of them, which is a build the type checker
// resolves and the source does not spell
func confirmSeveral(context *GroupContext) []VerifiedGroupContext {
	return []VerifiedGroupContext{{inner: context}}
}

// the zero value, which carries no context and confers nothing
func nothingAtAll() *VerifiedGroupContext {
	return &VerifiedGroupContext{}
}

// a COPY of one that already exists, which is not a new authority
func passItOn(verified *VerifiedGroupContext) *VerifiedGroupContext {
	held := *verified
	return &held
}

// a read of the field, which is not a write of it
func contextOf(verified *VerifiedGroupContext) *GroupContext {
	return verified.inner
}

// and the same field name filled on another type entirely
func fillTheOtherOne(context *GroupContext) *somethingElse {
	other := &somethingElse{}
	other.inner = context
	return other
}
`

// What the matcher must report out of the control, and by omission what it must walk past.
var verifiedGroupContextControlConstructions = []string{
	"confirmIt",
	"confirmItPositionally",
	"confirmSeveral",
	"fillItAfterwards",
}

// The declarations of this package that build a VerifiedGroupContext carrying a context, with why
// each is entitled to.
//
// ONE, and the gate below holds the derived class EQUAL to this in both directions, so a second
// one fails here until somebody says what it is. That is the whole point of keeping a gate at all
// after deleting the one this file replaces: the type makes a bypass a compile error for every
// package but this one, and inside this one the remaining question is which declarations are
// allowed to confer the authority. A row with no declaration is a claim that outlived what it
// described; a declaration with no row is a new door onto the epoch a cache believes it is in,
// added without the conversation.
var verifiedGroupContextConstructionSites = map[string]string{
	"(*KeySchedule).ConfirmGroupContext": "the one place in this package where a group context stops " +
		"being octets somebody sent and becomes a value this client vouches for. It takes no group " +
		"context at all -- there is nothing in its signature to launder -- and answers the one its own " +
		"schedule was derived over, once the confirmation tag proves a holder of this epoch's " +
		"confirmation key named it",
}

// TestEveryConstructionOfAVerifiedGroupContextIsClassifiedHere is rule 5 over the class that
// replaced an AST walk three rounds could not make hold.
//
// It runs on the control first, which is what says the matcher reads anything at all, and then on
// the real source. The reflection half in front of both is not decoration: it is what makes the
// narrow scan legitimate. A field that became exported is a field any package can fill, and this
// whole file would then be watching one package out of every package there is.
func TestEveryConstructionOfAVerifiedGroupContextIsClassifiedHere(t *testing.T) {
	// the compiler enforced half of the scope, asserted rather than assumed
	verified := reflect.TypeOf(VerifiedGroupContext{})
	if verified.NumField() != 1 {
		t.Fatalf("%s declares %d fields; it holds exactly one, and a second is a second thing a construction could get wrong",
			verifiedGroupContextTypeName, verified.NumField())
	}
	field := verified.Field(0)
	if field.IsExported() {
		t.Fatalf("%s.%s is exported, so a declaration in ANY package can build a verified context around whatever it decoded, and the type no longer says anything at all",
			verifiedGroupContextTypeName, field.Name)
	}
	if field.Name != verifiedGroupContextFieldName {
		t.Fatalf("%s holds its context in %s and this file's derivation reads %s, so the assignment arm of the class is empty",
			verifiedGroupContextTypeName, field.Name, verifiedGroupContextFieldName)
	}
	if field.Type != reflect.TypeOf((*GroupContext)(nil)) {
		t.Fatalf("%s.%s is a %s; it is a POINTER to a group context so that the zero value carries nil and every door can refuse it, and a value there would make the zero value read as the empty group at epoch 0",
			verifiedGroupContextTypeName, field.Name, field.Type)
	}

	control := typeCheckedBodiesOfText(t, "the verified group context control", verifiedGroupContextControl)
	built, judged := verifiedGroupContextConstructionsIn(control)
	if judged == 0 {
		t.Fatal("the matcher judged no construction in the control, so it would report a clean run over any package at all")
	}
	if reported := slices.Sorted(maps.Keys(built)); !slices.Equal(reported, verifiedGroupContextControlConstructions) {
		t.Fatalf("the rule read %v out of the control as building a verified context, want %v; one that reads only keyed elements walks past the positional build, one that reads only literals walks past the assignment, and one that reads the field NAME rather than the type it belongs to reports a build of something else",
			reported, verifiedGroupContextControlConstructions)
	}

	checked := typeCheckedBodiesOf(t, ".")
	if len(checked.paths) == 0 {
		t.Fatal("this package holds no non test source, so the gate scanned nothing")
	}
	found, realJudged := verifiedGroupContextConstructionsIn(checked)
	if realJudged == 0 {
		t.Fatalf("no construction of a %s was resolved in this package, and its constructor certainly builds one, so this gate is not reading what it claims to",
			verifiedGroupContextTypeName)
	}
	classified := slices.Sorted(maps.Keys(verifiedGroupContextConstructionSites))
	if names := slices.Sorted(maps.Keys(found)); !slices.Equal(names, classified) {
		t.Fatalf("%v build a %s and this table names %v; a construction with no row is a new door onto the epoch a cache believes it is in, and a row with no construction is a claim that outlived what it described",
			names, verifiedGroupContextTypeName, classified)
	}
	for _, name := range classified {
		if verifiedGroupContextConstructionSites[name] == "" {
			t.Errorf("%s is classified with no account of what entitles it, which is the enumeration this gate exists to not be", name)
		}
		for _, one := range found[name] {
			t.Logf("%s at %s builds %q", name, one.where, one.how)
		}
	}
}

// TestNeitherWriterOfTheCacheBindingTakesABareGroupContext is the compile time property written
// down, over the class the write gate already derives rather than over a list.
//
// The three bypasses this design replaces are compile errors now, and a compile error is not
// something a test can report. What a test CAN report is the signature that makes them compile
// errors, and that is this: no declaration that writes the cache binding takes a *GroupContext at
// all, and every one of them takes the verified type. A widening back to *GroupContext -- the one
// edit that would let a decoded context reach the binding again in any spelling -- fails here.
func TestNeitherWriterOfTheCacheBindingTakesABareGroupContext(t *testing.T) {
	written, _ := proposalBindingWritesIn(typeCheckedBodiesOf(t, "."))
	if len(written) == 0 {
		t.Fatal("no declaration of this package writes the cache binding, so this gate demands nothing")
	}
	cache := reflect.TypeOf(&ProposalCache{})
	bare := reflect.TypeOf((*GroupContext)(nil))
	confirmed := reflect.TypeOf((*VerifiedGroupContext)(nil))
	for _, name := range slices.Sorted(maps.Keys(written)) {
		// the writers are a plain function and methods of the cache, which are the two
		// shapes this package's binding writers take; a writer somewhere else is reported
		// rather than skipped, because a signature nothing here can read is one nothing
		// here holds
		signature, held := bindingWriterSignature(cache, name)
		if !held {
			t.Errorf("%s writes the cache binding and is neither a package level function this gate can find nor a method of *%s, so nothing checks what it takes",
				name, epochCacheTypeName)
			continue
		}
		takesConfirmed := false
		for at := 0; at < signature.NumIn(); at++ {
			if signature.In(at) == bare {
				t.Errorf("%s writes the cache binding and takes a %s; every group context names some epoch and this package decodes one straight off peer octets, so that parameter is a claim about a struct's fields and not about anybody's authority -- take a %s, whose only constructor confirmed it",
					name, bare, confirmed)
			}
			if signature.In(at) == confirmed {
				takesConfirmed = true
			}
		}
		if !takesConfirmed {
			t.Errorf("%s writes the cache binding and takes no %s, so nothing says where the epoch it writes came from",
				name, confirmed)
		}
	}
}

// bindingWriterSignature answers the compiled signature of one binding writer, named the way this
// package's tables name declarations.
//
// The method arm is read off the cache's own method set and the function arm off the one exported
// constructor there is, because those are the two shapes a binding writer takes here. A name it
// cannot resolve answers false rather than being skipped, which is what the caller reports.
func bindingWriterSignature(cache reflect.Type, name string) (reflect.Type, bool) {
	if bare, isMethod := strings.CutPrefix(name, "(*"+epochCacheTypeName+")."); isMethod {
		method, held := cache.MethodByName(bare)
		if !held {
			return nil, false
		}
		return method.Type, true
	}
	if name == "NewProposalCache" {
		return reflect.TypeOf(NewProposalCache), true
	}
	return nil, false
}

// ---------------------------------------------------------------------------
// what the constructor actually establishes
// ---------------------------------------------------------------------------

// testConfirmedScheduleOver is one epoch's key schedule, derived the way a JOINER derives one:
// out of a joiner secret and a psk secret, over the group context named.
//
// The joiner path and not NewKeyScheduleFromEpochSecret, and the difference is the whole property
// these tests are about. The epoch secret of the joiner path is
// ExpandWithLabel(member_secret, "epoch", group_context), so the context is mixed INTO the secret
// every key of the epoch descends from -- change one octet of it and confirmation_key changes with
// it. NewKeyScheduleFromEpochSecret takes the epoch secret from its caller, which is the group
// CREATION path: there the context and the secret are both this client's own, so a fixture built
// that way could not tell a confirmed context from an unconfirmed one at all.
//
// The two secrets are fixed rather than random, so that two schedules over two contexts differ in
// exactly one thing.
func testConfirmedScheduleOver(t *testing.T, groupContext *GroupContext) *KeySchedule {
	t.Helper()
	crypto := testCrypto(t)
	nh := crypto.HashSize()
	schedule, err := NewKeyScheduleFromJoiner(crypto,
		bytes.Repeat([]byte{0x4a}, nh), bytes.Repeat([]byte{0x5b}, nh), groupContext)
	if err != nil {
		t.Fatalf("a key schedule over epoch %d of group %x: %v",
			groupContext.Epoch, groupContext.GroupId, err)
	}
	return schedule
}

// testVerifiedContextAt is the group context of one epoch with its authority established the one
// way this package establishes it, for the tests that need a cache bound somewhere.
//
// The tag is the schedule's OWN, which is what a creator's is and what a member recomputing a
// commit's compares against. What that fixture cannot demonstrate -- that a tag from one epoch
// does not confirm another -- is the subject of a test of its own below rather than something
// this helper is asked to carry.
func testVerifiedContextAt(t *testing.T, groupContext *GroupContext) *VerifiedGroupContext {
	t.Helper()
	schedule := testConfirmedScheduleOver(t, groupContext)
	verified, err := schedule.ConfirmGroupContext(
		schedule.ConfirmationTag(groupContext.ConfirmedTranscriptHash))
	if err != nil {
		t.Fatalf("ConfirmGroupContext over epoch %d of group %x: %v",
			groupContext.Epoch, groupContext.GroupId, err)
	}
	return verified
}

// TestConfirmGroupContextAnswersTheContextItsOwnScheduleWasDerivedOver is the accepting half.
//
// Every field is compared and not only the two the cache binds to, because the value this hands
// back is the whole context and a constructor that answered the right group at the wrong tree hash
// would be handing a caller an epoch nobody published.
//
// The fixture carries an EXTENSION rather than none, and that is not decoration. The codec has one
// spelling for an absent vector and an empty one, so ReadExtensions never answers nil -- a fixture
// with no extensions would compare a nil slice against an empty one and fail for a reason that is
// the codec convention rather than this constructor. Carrying one also says the whole context
// survives the decode, which is the claim being made.
func TestConfirmGroupContextAnswersTheContextItsOwnScheduleWasDerivedOver(t *testing.T) {
	context := &GroupContext{
		Version:                 ProtocolVersionMls10,
		CipherSuite:             CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:                 []byte("a group"),
		Epoch:                   7,
		TreeHash:                bytes.Repeat([]byte{0x31}, 32),
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0x32}, 32),
		Extensions: []Extension{{
			ExtensionType: ExtensionTypeRequiredCapabilities,
			ExtensionData: []byte{0x00, 0x00, 0x00},
		}},
	}
	schedule := testConfirmedScheduleOver(t, context)
	verified, err := schedule.ConfirmGroupContext(schedule.ConfirmationTag(context.ConfirmedTranscriptHash))
	if err != nil {
		t.Fatalf("ConfirmGroupContext with this schedule's own tag: %v", err)
	}
	answered := verified.Context()
	if answered == nil {
		t.Fatal("a confirmed context answered nothing, so every door below would refuse it")
	}
	if !reflect.DeepEqual(answered, context) {
		t.Errorf("ConfirmGroupContext answered %+v, want %+v; it decodes the bytes this epoch expanded over, so a difference here is the answer describing an epoch the keys were not derived from",
			answered, context)
	}
}

// TestConfirmGroupContextRefusesATagFromAnotherEpoch is the refusing half, and it is the property
// the whole design rests on.
//
// Two schedules built from the SAME joiner secret and the SAME psk secret over two contexts that
// differ only in their epoch number. If the tag of one confirmed the other, then the value this
// type carries would say nothing about which epoch it belongs to -- which is exactly what a bare
// *GroupContext said, and this whole file would be ceremony.
func TestConfirmGroupContextRefusesATagFromAnotherEpoch(t *testing.T) {
	at7 := &GroupContext{
		Version:     ProtocolVersionMls10,
		CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:     []byte("a group"),
		Epoch:       7,
	}
	at8 := &GroupContext{
		Version:     ProtocolVersionMls10,
		CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:     []byte("a group"),
		Epoch:       8,
	}
	seven, eight := testConfirmedScheduleOver(t, at7), testConfirmedScheduleOver(t, at8)
	strangersTag := eight.ConfirmationTag(at8.ConfirmedTranscriptHash)
	if bytes.Equal(strangersTag, seven.ConfirmationTag(at7.ConfirmedTranscriptHash)) {
		t.Fatal("the two epochs produced the same confirmation tag, so the refusal below would hold nothing; the epoch secret is expanded over the group context and two contexts must not reach one key")
	}
	if _, err := seven.ConfirmGroupContext(strangersTag); !errors.Is(err, errUnconfirmedGroupContext) {
		t.Errorf("epoch 7's schedule confirmed its context under epoch 8's tag = %v, want errUnconfirmedGroupContext; a constructor that accepted a stranger's tag would confer this type's authority on any context at all",
			err)
	}
	// and the same over the GROUP rather than the epoch, because an epoch number is not an
	// identity: every group this client is in runs an epoch 7
	otherGroup := &GroupContext{
		Version:     ProtocolVersionMls10,
		CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:     []byte("another"),
		Epoch:       7,
	}
	other := testConfirmedScheduleOver(t, otherGroup)
	if _, err := seven.ConfirmGroupContext(other.ConfirmationTag(otherGroup.ConfirmedTranscriptHash)); !errors.Is(err, errUnconfirmedGroupContext) {
		t.Errorf("epoch 7 of one group confirmed itself under epoch 7 of another group's tag = %v, want errUnconfirmedGroupContext",
			err)
	}
}

// TestConfirmGroupContextRefusesAnEmptyOrTruncatedTag is the shape a caller reaches by passing
// whatever it happened to decode.
//
// The truncated case is the sharp one. A prefix comparison accepts every truncation of a valid
// tag, and a one octet tag is then a forgery an attacker finds in 256 tries; what refuses it is
// MacVerify's length check, reached through VerifyConfirmationTag, which is guardrail 8's whole
// point.
func TestConfirmGroupContextRefusesAnEmptyOrTruncatedTag(t *testing.T) {
	context := &GroupContext{
		Version:     ProtocolVersionMls10,
		CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:     []byte("a group"),
		Epoch:       3,
	}
	schedule := testConfirmedScheduleOver(t, context)
	whole := schedule.ConfirmationTag(context.ConfirmedTranscriptHash)
	if len(whole) < 2 {
		t.Fatalf("the confirmation tag is %d octets, so there is no truncation to make", len(whole))
	}
	for _, one := range []struct {
		name string
		tag  []byte
	}{
		{name: "no tag at all", tag: nil},
		{name: "an empty tag", tag: []byte{}},
		{name: "the tag one octet short", tag: whole[:len(whole)-1]},
		{name: "the tag's first octet alone", tag: whole[:1]},
		{name: "the tag with its last octet flipped", tag: append(bytes.Clone(whole[:len(whole)-1]), whole[len(whole)-1]^0x01)},
	} {
		if _, err := schedule.ConfirmGroupContext(one.tag); !errors.Is(err, errUnconfirmedGroupContext) {
			t.Errorf("ConfirmGroupContext with %s = %v, want errUnconfirmedGroupContext", one.name, err)
		}
	}
}

// TestConfirmGroupContextRefusesOverAnErasedEpoch is the state the whole erase discipline exists
// for, asked at this door.
//
// An erased confirmation_key is KDF.Nh ZERO bytes, which every party on earth can compute, so a
// tag over it authenticates nobody -- and a context confirmed by one would carry this type's
// authority on an attacker's say so.
//
// The refusal is ErrEpochErased and not errUnconfirmedGroupContext, which is the distinction a
// caller acts on: "the tag does not confirm this context" sends a member looking for a fork with
// a peer, and what actually happened is that this client dropped the epoch's secrets when it aged
// out of the window. Both are refusals; only one of them is true.
func TestConfirmGroupContextRefusesOverAnErasedEpoch(t *testing.T) {
	context := &GroupContext{
		Version:     ProtocolVersionMls10,
		CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:     []byte("a group"),
		Epoch:       4,
	}
	schedule := testConfirmedScheduleOver(t, context)
	tag := schedule.ConfirmationTag(context.ConfirmedTranscriptHash)
	if _, err := schedule.ConfirmGroupContext(tag); err != nil {
		t.Fatalf("the control: a live epoch refused its own tag: %v", err)
	}
	schedule.Zeroize()
	if _, err := schedule.ConfirmGroupContext(tag); !errors.Is(err, ErrEpochErased) {
		t.Errorf("an erased epoch confirmed a context = %v, want ErrEpochErased; its confirmation key is zeros, which every party can compute",
			err)
	}
}

// TestAConfirmedContextIsNotChangeableThroughWhatItHandsBack is the aliasing half.
//
// The value a cache binds to must not move under it. Context() answers a Clone, so a caller that
// rewrites the group id of what it was handed rewrites its own copy; the alternative -- handing
// back the pointer -- would let any holder of a verified context change which group it vouches
// for, after the vouching.
func TestAConfirmedContextIsNotChangeableThroughWhatItHandsBack(t *testing.T) {
	context := &GroupContext{
		Version:     ProtocolVersionMls10,
		CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:     []byte("a group"),
		Epoch:       5,
		TreeHash:    bytes.Repeat([]byte{0x71}, 32),
	}
	verified := testVerifiedContextAt(t, context)
	handed := verified.Context()
	handed.Epoch = 99
	handed.GroupId[0] ^= 0xff
	handed.TreeHash[0] ^= 0xff
	again := verified.Context()
	if again.Epoch != 5 {
		t.Errorf("a write through what Context answered moved the confirmed epoch to %d", again.Epoch)
	}
	if !bytes.Equal(again.GroupId, []byte("a group")) {
		t.Errorf("a write through what Context answered moved the confirmed group id to %x", again.GroupId)
	}
	if !bytes.Equal(again.TreeHash, bytes.Repeat([]byte{0x71}, 32)) {
		t.Errorf("a write through what Context answered moved the confirmed tree hash to %x", again.TreeHash)
	}
	// and the caller's own structure is not what the confirmed value holds either, since the
	// constructor decoded the schedule's bytes rather than keeping the argument
	context.Epoch = 98
	if verified.Context().Epoch != 5 {
		t.Error("a write through the caller's own context moved the confirmed epoch, so the confirmed value aliases the structure the schedule was built from")
	}
}

// TestTheZeroVerifiedGroupContextIsRefusedAtEveryDoor is the one shape another package can spell.
//
// mls.VerifiedGroupContext{} compiles anywhere, because a composite literal with no elements needs
// no access to the field. It carries nil, so what makes that harmless is not the type system but
// the refusal at each door, and this is what says every door has one.
func TestTheZeroVerifiedGroupContextIsRefusedAtEveryDoor(t *testing.T) {
	zero := &VerifiedGroupContext{}
	if got := zero.Context(); got != nil {
		t.Errorf("the zero verified context answered %+v, want nil; a value that vouches for nothing must say so rather than describing the empty group at epoch 0",
			got)
	}
	if _, err := NewProposalCache(zero); !errors.Is(err, ErrNilGroupContext) {
		t.Errorf("NewProposalCache(the zero verified context) = %v, want ErrNilGroupContext; a cache built from it would be bound to nothing, which is the one state in which a message can supply the epoch",
			err)
	}
	if err := testCache(t).Rebind(zero); !errors.Is(err, ErrNilGroupContext) {
		t.Errorf("Rebind(the zero verified context) = %v, want ErrNilGroupContext; a rebind that accepted it would empty the cache and leave it bound to nothing",
			err)
	}
	if got := (*VerifiedGroupContext)(nil).Context(); got != nil {
		t.Errorf("Context on no value at all answered %+v, want nil", got)
	}
}

// TestACacheBindsToTheEpochItsConfirmedContextNames joins this type to the thing it exists for.
//
// The cache's binding is unexported and this is in the same package, so the two fields it compares
// are read directly rather than inferred from a refusal: a test that only observed CheckEpoch
// would pass over a constructor that bound to the right epoch of the wrong group.
func TestACacheBindsToTheEpochItsConfirmedContextNames(t *testing.T) {
	context := testResolveContextAt([]byte("bound here"), 11)
	cache, err := NewProposalCache(testVerifiedContextAt(t, context))
	if err != nil {
		t.Fatalf("NewProposalCache over a confirmed context: %v", err)
	}
	if cache.binding == nil {
		t.Fatal("a cache built over a confirmed context is bound to nothing")
	}
	if !bytes.Equal(cache.binding.groupId, context.GroupId) || cache.binding.epoch != context.Epoch {
		t.Errorf("the cache bound itself to epoch %d of group %x, want epoch %d of group %x",
			cache.binding.epoch, cache.binding.groupId, context.Epoch, context.GroupId)
	}
	// and the binding does not alias the confirmed value's own storage
	verified := testVerifiedContextAt(t, context)
	rebound, err := NewProposalCache(verified)
	if err != nil {
		t.Fatalf("NewProposalCache over a second confirmed context: %v", err)
	}
	verified.inner.GroupId[0] ^= 0xff
	if !bytes.Equal(rebound.binding.groupId, context.GroupId) {
		t.Errorf("the binding followed a write into the confirmed context's own array to %x; a binding aliased to storage somebody else holds agrees with whatever that storage later says",
			rebound.binding.groupId)
	}
}
