package mls

// The class held here is "a COMPOSITION reaching a labelled construction", and it exists
// because the premise it replaces was TRUE FIELD BY FIELD and false for a sum.
//
// crypto_labels.go used to say that every value reaching a labelled construction arrived
// through a decode or an encode already bounded by syntax.MaxVectorLength, so the panic in
// mlsLabelBytes was unreachable. Every FIELD does obey that limit. A whole serialized
// structure wrapped in ONE opaque<V> does not: RefHash takes an AuthenticatedContent whose
// group_id, authenticated_data, proposal arms and signature are each bounded by a mebibyte
// and whose sum is not, and one valid proposal carrying a mebibyte credential took the
// process down in seven places -- (*ProposalCache).Store, (*AuthenticatedContent).ProposalRef,
// (*KeyPackage).Ref, SignWithLabel, VerifyWithLabel, DeriveJoinerSecret and EncryptWithLabel --
// the signature ones running BEFORE any application check a caller could have made.
//
// Two instruments hold it now and neither is a list. The boundary test below drives every
// construction AT the limit, ONE UNDER and ONE OVER, because the one fixture in this package
// that probed size -- proposal_ceiling_test.go's testEnormousProposal, at MaxVectorLength-64
// of extension data -- lands about six octets under the threshold, which is to say the only
// size probe here exercised the largest proposal that does not panic. The gate below derives
// the class off the source: it anchors on the declaration that PANICS on an encoder's
// refusal, walks BACK to every parameter whose bytes reach it, and requires every value this
// package builds with a syntax encoder and sends to one of them to have been bounded first.

import (
	"errors"
	"fmt"
	"go/ast"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// ---------------------------------------------------------------------------
// the boundary itself, at every construction a composition reaches
// ---------------------------------------------------------------------------

// One path from a value this package builds to a labelled construction, with the size of
// that value as the dial.
//
// compose and drive are two functions over one payload rather than one function answering
// both, because the assertion is about a length the test must be able to state exactly. A
// path whose drive succeeded for the wrong reason -- a composition that came out shorter
// than intended -- would read as a clean run, so compose is measured before drive is called
// and the measurement is the test's own precondition.
type labelledCompositionPath struct {
	name string
	// the composition this path hands to a labelled construction, at a payload size
	compose func(t *testing.T, payload int) []byte
	// the path itself, driven with that payload
	drive func(t *testing.T, crypto CryptoProvider, payload int) error
	// what the path answers for a composition that FITS. nil for the constructions that
	// have nothing further to say.
	fits error
}

// labelledCompositionPaths is every route from a value this package encodes to a single
// length prefixed field of a labelled construction, driven end to end.
//
// It is a table, and what keeps it honest is that it is not the gate:
// TestEveryCompositionEnteringALabelledConstructionIsBoundedBeforeItGetsThere derives the
// same set off the source and fails when the two disagree. This one is what says the
// derived set is a set of REAL crashes rather than a set of call sites, which no amount of
// walking the syntax can say.
func labelledCompositionPaths() []labelledCompositionPath {
	return []labelledCompositionPath{
		{
			name: "(*AuthenticatedContent).ProposalRef",
			compose: func(t *testing.T, payload int) []byte {
				return mustMarshalForSize(t, enormousProposalContent(t, payload))
			},
			drive: func(t *testing.T, crypto CryptoProvider, payload int) error {
				_, err := enormousProposalContent(t, payload).ProposalRef(crypto)
				return err
			},
		},
		{
			// the site the reviewer reached. Store computes the reference BEFORE every
			// ceiling it has -- its own doc pins that order, because the reference is the
			// key and a ceiling asked first would refuse a re-delivery of a message the
			// cache already holds -- so every ceiling added last commit sits downstream of
			// the crash.
			name: "(*ProposalCache).Store",
			compose: func(t *testing.T, payload int) []byte {
				return mustMarshalForSize(t, enormousProposalContent(t, payload))
			},
			drive: func(t *testing.T, crypto CryptoProvider, payload int) error {
				_, err := testCache(t).Store(crypto, testResolveContext(), enormousProposalContent(t, payload))
				return err
			},
		},
		{
			name: "(*KeyPackage).Ref",
			compose: func(t *testing.T, payload int) []byte {
				return mustMarshalForSize(t, enormousKeyPackage(t, payload))
			},
			drive: func(t *testing.T, crypto CryptoProvider, payload int) error {
				_, err := enormousKeyPackage(t, payload).Ref(crypto)
				return err
			},
		},
		{
			// the worst of them, because it runs on the RECEIVE path of every signed
			// message and before any check the application layer could have made.
			name: "SignWithLabel and VerifyWithLabel over a FramedContentTBS",
			compose: func(t *testing.T, payload int) []byte {
				return enormousFramedContentTBS(t, payload)
			},
			drive: func(t *testing.T, crypto CryptoProvider, payload int) error {
				member := testIdentity(t, crypto, "alice")
				tbs := enormousFramedContentTBS(t, payload)
				signature, err := crypto.SignWithLabel(member.SigPriv, framedContentTBSLabel, tbs)
				if err != nil {
					return err
				}
				return crypto.VerifyWithLabel(member.SigPub, framedContentTBSLabel, tbs, signature)
			},
		},
		{
			name: "DeriveJoinerSecret over a GroupContext",
			compose: func(t *testing.T, payload int) []byte {
				return mustMarshalForSize(t, enormousGroupContext(payload))
			},
			drive: func(t *testing.T, crypto CryptoProvider, payload int) error {
				nh := crypto.HashSize()
				_, err := DeriveJoinerSecret(crypto, make([]byte, nh), make([]byte, nh),
					enormousGroupContext(payload))
				return err
			},
		},
		{
			name: "EncryptWithLabel and DecryptWithLabel over a GroupContext",
			compose: func(t *testing.T, payload int) []byte {
				return mustMarshalForSize(t, enormousGroupContext(payload))
			},
			drive: func(t *testing.T, crypto CryptoProvider, payload int) error {
				priv, pub, err := crypto.DeriveKeyPair(crypto.Random(32))
				if err != nil {
					return err
				}
				context := mustMarshalForSize(t, enormousGroupContext(payload))
				kemOutput, ciphertext, err := EncryptWithLabel(crypto, pub, "node", context, []byte("x"))
				if err != nil {
					return err
				}
				_, err = DecryptWithLabel(crypto, priv, "node", context, kemOutput, ciphertext)
				return err
			},
		},
		{
			// the member of this class the original report did not name. A PSKLabel inlines
			// a PreSharedKeyID whose psk_id and psk_nonce are each bounded on their own and
			// unbounded together, both of them arrive from the wire, and PskSecret hands the
			// result to ExpandWithLabel -- a provider method with no way to refuse.
			name: "PskSecret over a PSKLabel",
			compose: func(t *testing.T, payload int) []byte {
				id := enormousPskId(payload)
				encoded, err := encodePskLabel(&id, 0, 1)
				if err != nil {
					t.Fatalf("encodePskLabel at a psk id of %d octets: %v", payload, err)
				}
				return encoded
			},
			drive: func(t *testing.T, crypto CryptoProvider, payload int) error {
				id := enormousPskId(payload)
				_, err := PskSecret(crypto, []PreSharedKeyInput{
					{Id: id, Secret: make([]byte, crypto.HashSize())},
				})
				return err
			},
		},
	}
}

// An AuthenticatedContent carrying one group_context_extensions proposal of the requested
// size, which is proposal_ceiling_test.go's testEnormousProposal with the size made a
// parameter rather than frozen six octets under the threshold.
func enormousProposalContent(t *testing.T, payload int) *AuthenticatedContent {
	t.Helper()
	return testProposalContentAt(t, LeafIndex(0), []byte("group"), 1, &Proposal{
		ProposalType: ProposalTypeGroupContextExtensions,
		GroupContextExtensions: &GroupContextExtensions{Extensions: []Extension{{
			ExtensionType: ExtensionTypeRequiredCapabilities,
			ExtensionData: make([]byte, payload),
		}}},
	})
}

// A key package whose credential carries the requested size. The credential is where a
// peer's bytes sit in a structure this package hashes whole, and a decoder accepts it: it
// is one opaque<V> under the limit inside a composition over it.
func enormousKeyPackage(t *testing.T, payload int) *KeyPackage {
	t.Helper()
	crypto := testCrypto(t)
	keyPackage, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "alice"))
	keyPackage.LeafNode.Credential = BasicCredential(make([]byte, payload))
	return keyPackage
}

// The FramedContentTBS of that proposal, which is what every signature over a member
// message covers and what VerifyWithLabel is handed before anything else looks at it.
func enormousFramedContentTBS(t *testing.T, payload int) []byte {
	t.Helper()
	groupContext := mustMarshalForSize(t, testResolveContext())
	content := enormousProposalContent(t, payload)
	tbs, err := FramedContentTBSBytes(WireFormatPublicMessage, &content.Content, groupContext)
	if err != nil {
		t.Fatalf("FramedContentTBSBytes at a payload of %d octets: %v", payload, err)
	}
	return tbs
}

// A group context whose group_id carries the requested size. Every field of it is inside
// the limit and their sum need not be.
func enormousGroupContext(payload int) *GroupContext {
	return &GroupContext{
		Version:                 ProtocolVersionMls10,
		CipherSuite:             CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:                 make([]byte, payload),
		Epoch:                   1,
		TreeHash:                make([]byte, 32),
		ConfirmedTranscriptHash: make([]byte, 32),
	}
}

// An external psk id whose psk_id carries the requested size, with the nonce at the length
// Validate demands so that the path reaches marshalPskLabel rather than stopping short of it.
func enormousPskId(payload int) PreSharedKeyId {
	return PreSharedKeyId{
		PskType:  PskTypeExternal,
		PskId:    make([]byte, payload),
		PskNonce: make([]byte, 32),
	}
}

// syntax.Marshal with the error taken here, for the fixtures above whose whole job is to
// answer a length.
func mustMarshalForSize(t *testing.T, value syntax.Marshaler) []byte {
	t.Helper()
	encoded, err := syntax.Marshal(value)
	if err != nil {
		t.Fatalf("marshal a fixture for its size: %v", err)
	}
	return encoded
}

// The payload at which one path's composition is EXACTLY target octets, solved rather than
// computed from a formula.
//
// Solved because a formula here would be this test's own second opinion about an encoding,
// and the boundary is the whole assertion: a case that meant to sit one octet over and sat
// one octet under would pass while proving nothing. The first probe is deliberately below
// the target so that no intermediate value asks the encoder for a FIELD past its own limit,
// which is a different refusal from the one under test.
func payloadComposingTo(t *testing.T, path labelledCompositionPath, target int) int {
	t.Helper()
	payload := target - 4096
	for attempt := 0; attempt < 8; attempt++ {
		composed := len(path.compose(t, payload))
		if composed == target {
			return payload
		}
		payload += target - composed
		if payload < 0 {
			t.Fatalf("%s: no payload composes to %d octets", path.name, target)
		}
	}
	t.Fatalf("%s: solving for a composition of %d octets did not converge", path.name, target)
	return 0
}

// The outcome of one drive, with a panic reported as itself.
//
// The recover is the point rather than a courtesy. The defect being closed is a PANIC, and
// a test that only read the error would report a process kill as a failed assertion about a
// return value, which is how the ceilings added last commit were believed to cover a path
// that crashed before reaching them.
func labelledDriveOutcome(t *testing.T, crypto CryptoProvider, path labelledCompositionPath,
	payload int) (err error, recovered any) {

	t.Helper()
	defer func() { recovered = recover() }()
	return path.drive(t, crypto, payload), nil
}

// Every labelled construction refuses a composition past one field's limit, and accepts one
// at it.
//
// THREE SIZES AND THE MIDDLE ONE IS THE ASSERTION. One over says the refusal exists; at the
// limit and one under say the refusal is the RIGHT one, which is what an off by one bound
// gets wrong in the direction no crash reports. A gate written only against the crash would
// be satisfied by refusing everything.
func TestEveryLabelledConstructionRefusesACompositionPastOneFieldsLimit(t *testing.T) {
	crypto := testCrypto(t)
	for _, path := range labelledCompositionPaths() {
		t.Run(path.name, func(t *testing.T) {
			for _, size := range []struct {
				name    string
				target  int
				refused bool
			}{
				{name: "one octet under one field's limit", target: syntax.MaxVectorLength - 1},
				{name: "exactly one field's limit", target: syntax.MaxVectorLength},
				{name: "one octet over one field's limit", target: syntax.MaxVectorLength + 1, refused: true},
			} {
				payload := payloadComposingTo(t, path, size.target)
				if composed := len(path.compose(t, payload)); composed != size.target {
					t.Fatalf("%s: the composition is %d octets, want %d", size.name, composed, size.target)
				}
				err, recovered := labelledDriveOutcome(t, crypto, path, payload)
				if recovered != nil {
					t.Fatalf("%s: the path PANICKED rather than answering: %v", size.name, recovered)
				}
				if size.refused {
					if !errors.Is(err, syntax.ErrLengthExceedsMax) {
						t.Fatalf("%s: answered %v, want syntax.ErrLengthExceedsMax", size.name, err)
					}
					continue
				}
				if path.fits == nil && err != nil {
					t.Fatalf("%s: a composition that FITS was refused with %v", size.name, err)
				}
				if path.fits != nil && !errors.Is(err, path.fits) {
					t.Fatalf("%s: answered %v, want %v", size.name, err, path.fits)
				}
				if errors.Is(err, syntax.ErrLengthExceedsMax) {
					t.Fatalf("%s: a composition of exactly one field's worth was refused as too long", size.name)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// the class, derived off the source rather than listed
// ---------------------------------------------------------------------------

// The rendered type of every parameter of every declaration, keyed as a frame names one.
//
// A composition is BYTES, and this is what stops the walk at a parameter that cannot carry
// one. Without it a CryptoProvider handed down four frames drags every declaration in the
// package that takes a provider into the class, because ExpandWithLabel writes its LENGTH
// argument into the same preimage as its context.
func labelledParameterTypes(sources []parsedSource) map[string]string {
	types := map[string]string{}
	for _, source := range sources {
		for _, declaration := range source.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			receiver := source.receiverOf(function)
			for _, field := range function.Type.Params.List {
				rendered := source.render(field.Type)
				for _, written := range field.Names {
					frame := labelledFrame{receiver: receiver, name: function.Name.Name, parameter: written.Name}
					types[frame.String()] = rendered
				}
			}
		}
	}
	return types
}

// Every name this package declares as a slice of bytes, so that a parameter typed
// SignaturePublicKey or ProposalRef is read as the byte carrier it is.
//
// Derived off the type declarations rather than listed, for rule 5's reason one layer down:
// a hand written list of byte-slice names understates itself the moment somebody declares
// another one, and the understatement here is a whole branch of the walk going unwalked.
func labelledByteSliceTypes(sources []parsedSource) map[string]bool {
	named := map[string]bool{"[]byte": true}
	for _, source := range sources {
		for _, declaration := range source.file.Decls {
			generic, isGeneric := declaration.(*ast.GenDecl)
			if !isGeneric {
				continue
			}
			for _, specification := range generic.Specs {
				typed, isType := specification.(*ast.TypeSpec)
				if !isType {
					continue
				}
				if source.render(typed.Type) == "[]byte" {
					named[typed.Name.Name] = true
				}
			}
		}
	}
	return named
}

// Whether one node mentions any of a set of identifiers.
func labelledMentions(node ast.Node, names map[string]bool) bool {
	found := false
	ast.Inspect(node, func(inner ast.Node) bool {
		if identifier, isIdentifier := inner.(*ast.Ident); isIdentifier && names[identifier.Name] {
			found = true
		}
		return true
	})
	return found
}

// The name of the syntax encoder a call expression is, or the empty string.
//
// A COMPOSITION in the sense this file uses the word is what one of these answers: the whole
// serialized form of a structure, whose length is the SUM of its fields and is bounded by
// nothing. syntax.Marshal bounds each field it writes and says nothing about the total,
// which is precisely the gap -- it answers 1050064 octets happily and the labelled field
// that wraps them refuses.
func labelledCompositionRoot(call *ast.CallExpr) string {
	selector, isSelector := call.Fun.(*ast.SelectorExpr)
	if !isSelector {
		return ""
	}
	if base, isIdentifier := selector.X.(*ast.Ident); isIdentifier &&
		base.Name == "syntax" && strings.HasPrefix(selector.Sel.Name, "Marshal") {
		return "syntax." + selector.Sel.Name
	}
	// a Writer's own finaliser, which is what every hand assembled preimage in this package
	// ends with
	if selector.Sel.Name == "Bytes" && len(call.Args) == 0 {
		return "Writer.Bytes"
	}
	return ""
}

// The encoder a call expression answers a composition from, following calls to declarations
// of this package that answer one themselves.
func labelledCompositionOf(call *ast.CallExpr, producers map[string]bool) string {
	if root := labelledCompositionRoot(call); root != "" {
		return root
	}
	name := ""
	switch called := call.Fun.(type) {
	case *ast.Ident:
		name = called.Name
	case *ast.SelectorExpr:
		name = called.Sel.Name
	default:
		return ""
	}
	if producers[name] {
		return name
	}
	return ""
}

// Every local of one body that holds a composition, and the encoder it came from.
func labelledCompositionLocals(body *ast.BlockStmt, producers map[string]bool) map[string]string {
	locals := map[string]string{}
	for spreading := true; spreading; {
		spreading = false
		ast.Inspect(body, func(node ast.Node) bool {
			assignment, isAssignment := node.(*ast.AssignStmt)
			if !isAssignment {
				return true
			}
			from := ""
			for _, value := range assignment.Rhs {
				if call, isCall := value.(*ast.CallExpr); isCall {
					if of := labelledCompositionOf(call, producers); of != "" {
						from = of
					}
				}
				// an alias of a composition is the composition, which is the shape the
				// labelled path walk in crypto_labels_test.go records nine surviving
				// mutants for
				if identifier, isIdentifier := value.(*ast.Ident); isIdentifier && locals[identifier.Name] != "" {
					from = locals[identifier.Name]
				}
			}
			if from == "" {
				return true
			}
			for _, target := range assignment.Lhs {
				written, isIdentifier := target.(*ast.Ident)
				if !isIdentifier || written.Name == "_" || written.Name == "err" {
					continue
				}
				if locals[written.Name] == "" {
					locals[written.Name] = from
					spreading = true
				}
			}
			return true
		})
	}
	return locals
}

// Whether one declaration ANSWERS a composition, so that a caller assigning from it holds
// one.
func labelledAnswersAComposition(function *ast.FuncDecl, producers map[string]bool) bool {
	locals := labelledCompositionLocals(function.Body, producers)
	answered := map[string]bool{}
	for name := range locals {
		answered[name] = true
	}
	found := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		returned, isReturn := node.(*ast.ReturnStmt)
		if !isReturn {
			return true
		}
		for _, result := range returned.Results {
			if call, isCall := result.(*ast.CallExpr); isCall && labelledCompositionOf(call, producers) != "" {
				found = true
			}
			if labelledMentions(result, answered) {
				found = true
			}
		}
		return true
	})
	return found
}

// Every declaration of this package that answers a composition, to a fixpoint.
func labelledCompositionProducers(index map[string][]labelledDeclaration, t *testing.T) map[string]bool {
	producers := map[string]bool{}
	for spreading := true; spreading; {
		spreading = false
		for name, declarations := range index {
			if producers[name] {
				continue
			}
			for _, declaration := range declarations {
				function := declaration.source.declarationOf(t, declaration.receiver, declaration.name)
				if labelledAnswersAComposition(function, producers) {
					producers[name] = true
					spreading = true
					break
				}
			}
		}
	}
	return producers
}

// The one comparison in this package that refuses a length, found rather than named: a body
// that reads BOTH syntax.MaxVectorLength and syntax.ErrLengthExceedsMax is a body deciding
// whether something fits in one length prefixed field.
func labelledRefusesALength(source parsedSource, function *ast.FuncDecl) bool {
	rendered := source.render(function)
	return strings.Contains(rendered, "syntax.MaxVectorLength") &&
		strings.Contains(rendered, "syntax.ErrLengthExceedsMax")
}

// Every (declaration, parameter) this package BOUNDS before it forwards it, to a fixpoint
// and positionally.
//
// Positionally rather than by name, because what makes SignWithLabel safe is not that it
// mentions a refusal somewhere in its body but that the argument it hands over is the one
// the refusal judges. A by-name rule would read a body that checked its label and forwarded
// its content unbounded as a body that checks both.
//
// The base case is a parameter, so the transitive step is a parameter too: a declaration
// bounds its own parameter when it passes it to a declaration that bounds the parameter it
// LANDS ON. That is what carries the refusal in checkLabelledFieldLength out through
// checkLabelledConstruction to SignWithLabel, VerifyWithLabel, EncryptWithLabel and
// DecryptWithLabel without any of the four being named here.
func labelledBoundedParameters(t *testing.T, sources []parsedSource,
	index map[string][]labelledDeclaration,
	bounds func(parsedSource, *ast.FuncDecl, string) bool) map[string]bool {

	refused := map[string]bool{}
	for _, source := range sources {
		for _, declaration := range source.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			receiver := source.receiverOf(function)
			// the parameter the bound is over, and only that one
			for _, field := range function.Type.Params.List {
				for _, written := range field.Names {
					if bounds(source, function, written.Name) {
						refused[labelledFrame{receiver: receiver, name: function.Name.Name,
							parameter: written.Name}.String()] = true
					}
				}
			}
		}
	}
	for spreading := true; spreading; {
		spreading = false
		for _, declarations := range index {
			for _, declaration := range declarations {
				function := declaration.source.declarationOf(t, declaration.receiver, declaration.name)
				ast.Inspect(function.Body, func(node ast.Node) bool {
					call, isCall := node.(*ast.CallExpr)
					if !isCall {
						return true
					}
					for _, callee := range labelledCalleesOf(index, call) {
						for i, argument := range call.Args {
							landing := labelledFrame{receiver: callee.receiver, name: callee.name,
								parameter: callee.parameters[i]}
							if !refused[landing.String()] {
								continue
							}
							for _, field := range function.Type.Params.List {
								for _, written := range field.Names {
									if !labelledMentions(argument, map[string]bool{written.Name: true}) {
										continue
									}
									here := labelledFrame{receiver: declaration.receiver,
										name: declaration.name, parameter: written.Name}
									if !refused[here.String()] {
										refused[here.String()] = true
										spreading = true
									}
								}
							}
						}
					}
					return true
				})
			}
		}
	}
	return refused
}

// Whether one declaration REFUSES a parameter for being too long: it is a body that decides
// whether something fits in one length prefixed field, and the thing it decides about is
// this parameter.
func labelledRefusesParameter(source parsedSource, function *ast.FuncDecl, parameter string) bool {
	if !labelledRefusesALength(source, function) {
		return false
	}
	found := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		comparison, isBinary := node.(*ast.BinaryExpr)
		if !isBinary {
			return true
		}
		if !strings.Contains(source.render(comparison.Y), "syntax.MaxVectorLength") {
			return true
		}
		if labelledMentions(comparison.X, labelledAliasesOf(function, parameter)) {
			found = true
		}
		return true
	})
	return found
}

// Whether one declaration TRUNCATES a parameter to a length of its own before forwarding it.
//
// The OTHER way a value reaches a labelled field bounded, and it is the way RFC 9420 itself
// prescribes rather than a weaker substitute for a refusal. Section 6.3.2 derives the sender
// data key over a ciphertext_sample of the first KDF.Nh octets, so SenderDataKeyNonce hands
// ExpandWithLabel at most a hash's worth however long the message was. A refusal there would
// be wrong rather than stricter: a peer's whole PrivateMessage is meant to arrive.
//
// The high bound must not be read off the value's own length, and that is the line between
// the two: sample = sample[:nh] is a ceiling this declaration chose, and
// sample = sample[:len(sample)-1] is a length the caller still controls wearing a slice
// expression. Only the first bounds anything.
func labelledTruncatesParameter(source parsedSource, function *ast.FuncDecl, parameter string) bool {
	aliases := labelledAliasesOf(function, parameter)
	found := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		slice, isSlice := node.(*ast.SliceExpr)
		if !isSlice || slice.High == nil || slice.Low != nil {
			return true
		}
		if !labelledMentions(slice.X, aliases) {
			return true
		}
		if strings.Contains(source.render(slice.High), "len(") {
			return true
		}
		found = true
		return true
	})
	return found
}

// One parameter and every local of the same body that carries it.
//
// An alias is the shape this exists for, and it is the same shape crypto_labels_test.go's
// own flow walk records nine surviving mutants for: sample := ciphertext followed by
// sample = sample[:nh] bounds the ciphertext, and a matcher reading only the parameter's own
// name sees a body that never touches it.
func labelledAliasesOf(function *ast.FuncDecl, parameter string) map[string]bool {
	aliases := map[string]bool{parameter: true}
	for spreading := true; spreading; {
		spreading = false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assignment, isAssignment := node.(*ast.AssignStmt)
			if !isAssignment {
				return true
			}
			carries := false
			for _, value := range assignment.Rhs {
				if labelledMentions(value, aliases) {
					carries = true
				}
			}
			if !carries {
				return true
			}
			for _, target := range assignment.Lhs {
				written, isIdentifier := target.(*ast.Ident)
				if !isIdentifier || written.Name == "_" || aliases[written.Name] {
					continue
				}
				aliases[written.Name] = true
				spreading = true
			}
			return true
		})
	}
	return aliases
}

// Whether one declaration bounds the composition it ANSWERS, which is the other half of the
// rule: a producer either refuses its own result or hands an unbounded one to its caller.
func labelledBoundsWhatItAnswers(source parsedSource, function *ast.FuncDecl,
	producers map[string]bool) bool {

	if labelledRefusesALength(source, function) {
		return true
	}
	answered := map[string]bool{}
	for name := range labelledCompositionLocals(function.Body, producers) {
		answered[name] = true
	}
	found := false
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		identifier, isIdentifier := call.Fun.(*ast.Ident)
		if !isIdentifier || !strings.HasPrefix(identifier.Name, "checkLabelled") {
			return true
		}
		for _, argument := range call.Args {
			if labelledMentions(argument, answered) {
				found = true
			}
		}
		return true
	})
	return found
}

// The (declaration, parameter) pairs where an encoder's refusal becomes a PANIC, which is
// the anchor everything below hangs off.
//
// Derived and not named. A declaration qualifies when it panics on a value carrying an error
// it took from a composition producer -- which is exactly "this body turned an encoder's no
// into a process exit" and is what separates mlsLabelBytes from the five other panics in
// this package, none of which is reached from a syntax encoder.
func labelledPanicAnchors(t *testing.T, sources []parsedSource, producers map[string]bool) []labelledFrame {
	anchors := []labelledFrame{}
	for _, source := range sources {
		for _, declaration := range source.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			panicked := map[string]bool{}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, isCall := node.(*ast.CallExpr)
				if !isCall {
					return true
				}
				if identifier, isIdentifier := call.Fun.(*ast.Ident); !isIdentifier || identifier.Name != "panic" {
					return true
				}
				for _, argument := range call.Args {
					ast.Inspect(argument, func(inner ast.Node) bool {
						if named, isNamed := inner.(*ast.Ident); isNamed {
							panicked[named.Name] = true
						}
						return true
					})
				}
				return true
			})
			if len(panicked) == 0 {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				assignment, isAssignment := node.(*ast.AssignStmt)
				if !isAssignment {
					return true
				}
				carries := false
				for _, target := range assignment.Lhs {
					if identifier, isIdentifier := target.(*ast.Ident); isIdentifier && panicked[identifier.Name] {
						carries = true
					}
				}
				if !carries {
					return true
				}
				for _, value := range assignment.Rhs {
					call, isCall := value.(*ast.CallExpr)
					if !isCall || labelledCompositionOf(call, producers) == "" {
						continue
					}
					for _, field := range function.Type.Params.List {
						for _, written := range field.Names {
							if !labelledMentions(call, map[string]bool{written.Name: true}) {
								continue
							}
							anchors = append(anchors, labelledFrame{
								receiver:  source.receiverOf(function),
								name:      function.Name.Name,
								parameter: written.Name,
							})
						}
					}
				}
				return true
			})
		}
	}
	return anchors
}

// Every (declaration, parameter) whose bytes reach a panicking encoder, walked BACKWARDS
// from the anchor.
//
// The walk stops at a position the declaration REFUSES, and that is the whole shape of the
// answer this landed: where a signature can carry a refusal the construction carries it, and
// where it cannot the caller bounds what it builds. A refused position stays in the set --
// a reviewer needs to see it, and the composition edges that end there are closed BY it --
// but nothing behind it is dragged in, because nothing behind it can reach the panic.
func labelledFieldPositions(t *testing.T, sources []parsedSource, index map[string][]labelledDeclaration,
	anchors []labelledFrame, refused map[string]bool) (positions map[string]bool) {

	types := labelledParameterTypes(sources)
	byteSlices := labelledByteSliceTypes(sources)
	forward := map[string][]string{}
	for _, declarations := range index {
		for _, declaration := range declarations {
			for _, parameter := range declaration.parameters {
				here := labelledFrame{receiver: declaration.receiver, name: declaration.name,
					parameter: parameter}
				if !byteSlices[types[here.String()]] {
					continue
				}
				for _, next := range labelledFlowFrom(declaration, t, index, parameter) {
					forward[here.String()] = append(forward[here.String()], next.String())
				}
			}
		}
	}
	// reaching is "the panic is still downstream of here". An anchor reaches it by
	// definition; a position reaches it unless its own declaration refuses the value, which
	// is what makes the walk stop at SignWithLabel rather than climbing into every caller
	// that ever signed anything.
	reaching := map[string]bool{}
	for _, anchor := range anchors {
		reaching[anchor.String()] = true
	}
	positions = map[string]bool{}
	for spreading := true; spreading; {
		spreading = false
		for from, targets := range forward {
			if positions[from] {
				continue
			}
			for _, to := range targets {
				if !reaching[to] {
					continue
				}
				positions[from] = true
				if !refused[from] {
					reaching[from] = true
				}
				spreading = true
				break
			}
		}
	}
	return positions
}

// One value this package builds with a syntax encoder, and the labelled construction it
// reaches.
type labelledCompositionEdge struct {
	file     string
	from     string
	producer string
	to       string
	closed   string
}

func (self labelledCompositionEdge) String() string {
	return fmt.Sprintf("%s %s: %s -> %s (%s)", self.file, self.from, self.producer, self.to, self.closed)
}

// Every composition this package builds that reaches a labelled construction, with how each
// one is closed.
func labelledCompositionEdges(t *testing.T, index map[string][]labelledDeclaration,
	producers map[string]bool, positions map[string]bool,
	refused map[string]bool, truncated map[string]bool) []string {

	edges := []string{}
	for _, declarations := range index {
		for _, declaration := range declarations {
			function := declaration.source.declarationOf(t, declaration.receiver, declaration.name)
			locals := labelledCompositionLocals(function.Body, producers)
			for local, producer := range locals {
				bounded := false
				for _, candidate := range index[producer] {
					if labelledBoundsWhatItAnswers(candidate.source,
						candidate.source.declarationOf(t, candidate.receiver, candidate.name), producers) {
						bounded = true
					}
				}
				for _, frame := range labelledFlowFrom(declaration, t, index, local) {
					if !positions[frame.String()] {
						continue
					}
					closed := ""
					switch {
					case refused[frame.String()]:
						closed = "refused at the construction"
					case truncated[frame.String()]:
						closed = "truncated at the construction"
					case bounded:
						closed = "bounded where it is built"
					default:
						closed = "NOTHING BOUNDS IT"
					}
					here := labelledFrame{receiver: declaration.receiver, name: declaration.name}
					edges = append(edges, labelledCompositionEdge{
						file: declaration.source.fileSet.Position(function.Pos()).Filename,
						from: strings.TrimSpace(here.String()), producer: producer,
						to: frame.String(), closed: closed,
					}.String())
				}
			}
		}
	}
	slices.Sort(edges)
	return slices.Compact(edges)
}

// The one place in this package where a syntax encoder's refusal becomes a panic.
//
// One entry and the gate compares both ways, so a SECOND declaration that turns an encoder's
// no into a process exit fails here rather than being walked from and never noticed. The
// five other panics in this package -- three in crypto.go, one in hpke.go, one in treekem.go
// -- are not reached from an encoder and are correctly outside this.
var labelledPanicAnchorFrames = []string{
	"mlsLabelBytes w",
}

// Every parameter of this package whose bytes reach the panicking encoder, and what stops
// them there.
//
// This is the FRONTIER of the class rather than the class itself: it is where a composition
// would have to arrive to reach a panic, and each entry says whether that position refuses
// an over long value, truncates it, or is open and leaves the bound to whoever built the
// value. The open ones are exactly the two constructions whose signatures cannot report a
// refusal -- the RFC 9420 section 5.2 reference makers, and the KDF label under a
// CryptoProvider method -- which is why the answer this landed is split rather than uniform.
//
// It is derived and compared both ways for the same reason the table below it is. A
// declaration that starts forwarding bytes into a labelled field appears here; one that
// stops refusing appears here with its parenthesis changed.
//
// mlsSignContent and mlsEncryptContext are open and that is not a gap: nothing calls either
// of them except the four entry points that refuse first, which is a fact this walk
// establishes rather than assumes -- a refused position is where the walk STOPS, so those
// two having no callers in this table is the statement that they have no unrefused ones.
//
// The six senderDataSecret rows are the walk over-approximating and are left in rather than
// filtered out. crypto_labels_test.go's flow relation spreads taint through a method call on
// a tainted local, so senderDataSecret taints the provider, the provider taints KDF.Nh, and
// KDF.Nh taints the ciphertext sample sliced with it -- a chain of three that ends at a
// context field the secret never enters. Over-approximating is the safe direction and the
// cost of it is a row; the alternative is a walk that decides for itself which flows are
// real, which is the class of judgement that let the premise this file replaces survive.
var labelledFieldFrontier = []string{
	"*KeySchedule.Export context (open, so a caller must bound what it sends)",
	"*suiteCryptoProvider.ExpandWithLabel context (open, so a caller must bound what it sends)",
	"*suiteCryptoProvider.SignWithLabel content (refused here)",
	"*suiteCryptoProvider.VerifyWithLabel content (refused here)",
	"DecryptWithLabel context (refused here)",
	"EncryptWithLabel context (refused here)",
	"MakeKeyPackageRef keyPackage (open, so a caller must bound what it sends)",
	"MakeProposalRef authenticatedContent (open, so a caller must bound what it sends)",
	"OpenPrivateMessage senderDataSecret (open, so a caller must bound what it sends)",
	"RefHash value (open, so a caller must bound what it sends)",
	"SealPrivateMessage senderDataSecret (open, so a caller must bound what it sends)",
	"SenderDataKeyNonce ciphertext (truncated here)",
	"SenderDataKeyNonce senderDataSecret (open, so a caller must bound what it sends)",
	"mlsEncryptContext context (open, so a caller must bound what it sends)",
	"mlsKdfLabel context (open, so a caller must bound what it sends)",
	"mlsSignContent content (open, so a caller must bound what it sends)",
	"openSenderData senderDataSecret (open, so a caller must bound what it sends)",
	"sealPrivateMessage senderDataSecret (open, so a caller must bound what it sends)",
	"sealSenderData senderDataSecret (open, so a caller must bound what it sends)",
}

// Every composition this package builds that reaches a labelled construction, and how each
// one is closed.
//
// A hand written list is what this project has understated fourteen times, so nothing here
// is trusted: the walk derives the same set from the syntax of the package on every run and
// the two are compared BOTH WAYS. A composition added anywhere in this package that reaches
// a labelled field appears here and fails; one deleted from this table fails as well; and a
// bound removed from either end changes the parenthesis rather than the line, so it fails
// too. The table is what a reviewer reads. The walk is what says the table is the class.
//
// Read down the right hand column and the shape of the answer is the whole of it. Where the
// construction's signature can carry a refusal it carries one, and the composition arrives
// unbounded on purpose -- a signature preimage IS the whole message and refusing to build
// one this side would be refusing to check a peer's. Where it cannot, the value is bounded
// at the declaration that BUILDS it, which is the only place upstream of RefHash and of a
// provider method that still has a caller to answer.
var labelledCompositionClass = []string{
	"framing_preimage.go *AuthenticatedContent.ProposalRef: marshalBoundedComposition -> MakeProposalRef authenticatedContent (bounded where it is built)",
	"framing_protect.go SignAuthenticatedContent: FramedContentTBSBytes -> *suiteCryptoProvider.SignWithLabel content (refused at the construction)",
	"framing_protect.go VerifyAuthenticatedContent: FramedContentTBSBytes -> *suiteCryptoProvider.VerifyWithLabel content (refused at the construction)",
	"key_package.go *KeyPackage.Ref: marshalBoundedComposition -> MakeKeyPackageRef keyPackage (bounded where it is built)",
	"key_package.go *KeyPackage.Validate: signedPreimage -> *suiteCryptoProvider.VerifyWithLabel content (refused at the construction)",
	"key_package.go NewKeyPackage: signedPreimage -> *suiteCryptoProvider.SignWithLabel content (refused at the construction)",
	"key_schedule.go DeriveJoinerSecret: marshalBoundedComposition -> *suiteCryptoProvider.ExpandWithLabel context (bounded where it is built)",
	"key_schedule.go NewKeyScheduleFromJoiner: marshalBoundedComposition -> *suiteCryptoProvider.ExpandWithLabel context (bounded where it is built)",
	"leaf_node.go *LeafNode.Sign: signatureContent -> *suiteCryptoProvider.SignWithLabel content (refused at the construction)",
	"leaf_node.go *LeafNode.VerifySignature: signatureContent -> *suiteCryptoProvider.VerifyWithLabel content (refused at the construction)",
	"psk.go PskSecret: marshalPskLabel -> *suiteCryptoProvider.ExpandWithLabel context (bounded where it is built)",
}

func TestEveryCompositionEnteringALabelledConstructionIsBoundedBeforeItGetsThere(t *testing.T) {
	sources := packageSources(t)
	index := labelledDeclarationsIn(sources)
	producers := labelledCompositionProducers(index, t)
	anchors := labelledPanicAnchors(t, sources, producers)

	anchored := []string{}
	for _, anchor := range anchors {
		anchored = append(anchored, anchor.String())
	}
	slices.Sort(anchored)
	anchored = slices.Compact(anchored)
	if !slices.Equal(anchored, labelledPanicAnchorFrames) {
		t.Fatalf("an encoder's refusal becomes a panic at\n%s\nand this gate knows of\n%s",
			strings.Join(anchored, "\n"), strings.Join(labelledPanicAnchorFrames, "\n"))
	}

	// the two shapes a declaration bounds what it forwards in, kept apart because they are
	// not the same statement: a refusal says the value cannot pass, a truncation says only
	// a fixed prefix of it does. Both stop the walk; only one of them is a refusal, and a
	// reviewer reading the table below needs to see which is which.
	refused := labelledBoundedParameters(t, sources, index, labelledRefusesParameter)
	truncated := labelledBoundedParameters(t, sources, index, labelledTruncatesParameter)
	bounded := map[string]bool{}
	for position := range refused {
		bounded[position] = true
	}
	for position := range truncated {
		bounded[position] = true
	}
	positions := labelledFieldPositions(t, sources, index, anchors, bounded)
	frontier := []string{}
	for position := range positions {
		switch {
		case refused[position]:
			frontier = append(frontier, position+" (refused here)")
		case truncated[position]:
			frontier = append(frontier, position+" (truncated here)")
		default:
			frontier = append(frontier, position+" (open, so a caller must bound what it sends)")
		}
	}
	slices.Sort(frontier)
	if !slices.Equal(frontier, labelledFieldFrontier) {
		t.Errorf("the bytes of this package reach the panicking encoder through\n%s\nand this gate knows of\n%s",
			strings.Join(frontier, "\n"), strings.Join(labelledFieldFrontier, "\n"))
	}

	edges := labelledCompositionEdges(t, index, producers, positions, refused, truncated)
	if !slices.Equal(edges, labelledCompositionClass) {
		t.Errorf("the compositions of this package reach a labelled construction as\n%s\nand this gate knows of\n%s",
			strings.Join(edges, "\n"), strings.Join(labelledCompositionClass, "\n"))
	}
	for _, edge := range edges {
		if strings.Contains(edge, "NOTHING BOUNDS IT") {
			t.Errorf("a composition reaches a labelled construction unbounded: %s", edge)
		}
	}
}
