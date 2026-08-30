// The framing layer's ValSem refusals, and the roster that says each of them still has a test.
//
// RFC 9420 section 6 is authenticated by two things this package already holds -- a signature and
// a membership tag -- and neither of them says anything about WHICH conversation the message
// belongs to. A valid signature says some member of some group signed these bytes in some epoch.
// ValSem002, ValSem003 and ValSem004 are what turn that into a statement about this group, this
// epoch, and a leaf that is actually occupied, so they are the rules a receive path cannot verify
// its way past, and they live here beside the roster rather than beside the codecs.
//
// The roster is the other half, and it is the half that has been worth having. A refusal is one
// `if` and a `return`; a refusal whose test was deleted, renamed away, or moved into a file the
// build no longer compiles is the same one `if` with nothing watching it, and no coverage
// percentage in go reports the difference between a branch a test drives and a branch a test
// merely walks past. So the roster is DERIVED -- off this package's own refusal sites and off its
// own test declarations -- rather than written down. Fifteen times on this project a hand written
// list of a class understated the class, and the plan's own draft of this test held ten sentinel
// names in a slice literal, which is exactly the shape that goes stale the day an eleventh
// refusal lands.
package mls

import (
	"bytes"
	"errors"
	"go/ast"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// ---------------------------------------------------------------------------
// ValSem002 and ValSem003, the group id and the epoch
// ---------------------------------------------------------------------------

// framingWideGroupId is a group id wide enough for a position sweep to mean something.
//
// framingTestMemberContent carries a two octet group id, which is the right size for a codec
// golden and the wrong size for this rule: over two octets a comparison that reads the first octet
// and a comparison that reads the whole thing disagree in exactly one place, and one place is a
// coincidence rather than a class. Every octet is a different value, so a comparison that summed,
// sorted or hashed the two ids would still have to see a difference.
func framingWideGroupId() []byte {
	id := make([]byte, 32)
	for i := range id {
		id[i] = byte(0xa0 + i)
	}
	return id
}

// framingNeighbouringEpochs is the epochs ValSem003 is judged against, derived from the one under
// test rather than being the +1 a rule's author pictures.
//
// The two that are not obvious are the interesting ones. epoch^(1<<32) differs from the epoch in
// its HIGH half alone, which is what a comparison narrowed to uint32 accepts -- and the epoch is a
// uint64 in RFC 9420 precisely because it is never reset, so a receiver comparing the low half
// would take a replay from four billion epochs ago as current. math.MaxUint64 is the saturating
// value a hostile peer writes when it wants a comparison to overflow rather than to differ.
func framingNeighbouringEpochs(epoch uint64) []uint64 {
	return []uint64{
		0,
		1,
		epoch - 1,
		epoch,
		epoch + 1,
		epoch ^ (1 << 32),
		math.MaxUint32,
		math.MaxUint64,
	}
}

// TestFramedContentContextRefusesWrongGroupId is ValSem002, over every octet of the group id and
// every length of it rather than over the one corruption somebody thought of.
//
// The sweep is rule 5's, and this project has the measurement behind it twice: a comparison that
// read a prefix passed a suite whose only case flipped octet zero, and a comparison written as
// bytes.HasPrefix passed a ban list that held six comparator names. Both shapes are refused here
// because the offending octet is at every position in turn, and because the length cases run past
// the end of the real id as well as short of it.
//
// The positive case is beside them, so the rule cannot be satisfied by a check that refuses
// everything -- which is the whole of what "wrong group id" would become if it did.
func TestFramedContentContextRefusesWrongGroupId(t *testing.T) {
	content := framingTestMemberContent()
	content.GroupId = framingWideGroupId()
	if err := CheckFramedContentContext(content, content.GroupId, content.Epoch); err != nil {
		t.Fatalf("the receiver's own group id and epoch were refused: %v", err)
	}
	// a copy rather than the same backing array, so what is compared is the VALUE, and a rule
	// that compared slice identity is not passing here on the argument being the same object
	if err := CheckFramedContentContext(content, bytes.Clone(content.GroupId), content.Epoch); err != nil {
		t.Fatalf("an equal group id in another array was refused: %v", err)
	}
	for at := range content.GroupId {
		for bit := 0; bit < 8; bit += 1 {
			other := bytes.Clone(content.GroupId)
			other[at] ^= 1 << uint(bit)
			err := CheckFramedContentContext(content, other, content.Epoch)
			if !errors.Is(err, errWrongGroupId) {
				t.Fatalf("bit %d of group id octet %d flipped: got %v, want errWrongGroupId", bit, at, err)
			}
			// and it is ValSem002 that refused it and not the epoch rule behind it
			if errors.Is(err, errWrongEpoch) {
				t.Fatalf("bit %d of group id octet %d flipped: answered errWrongEpoch too, and the epoch matches",
					bit, at)
			}
		}
	}
	// every truncation and every extension, which is the class a prefix comparison accepts
	for n := 0; n <= 2*len(content.GroupId); n += 1 {
		if n == len(content.GroupId) {
			continue
		}
		resized := make([]byte, n)
		copy(resized, content.GroupId)
		if err := CheckFramedContentContext(content, resized, content.Epoch); !errors.Is(err, errWrongGroupId) {
			t.Fatalf("a %d octet group id against this content's %d: got %v, want errWrongGroupId",
				n, len(content.GroupId), err)
		}
	}
	// a content wrong on BOTH counts is answered as ValSem002, which is the order this rule
	// states and the only case that can observe it. An epoch is a fact about a group, so a
	// message from another group has no epoch this receiver can compare it against, and a body
	// that answered ValSem003 here would be telling its caller that a stranger's message was one
	// of this group's own that had arrived late.
	bothWrong := bytes.Clone(content.GroupId)
	bothWrong[len(bothWrong)-1] ^= 0xff
	if err := CheckFramedContentContext(content, bothWrong, content.Epoch+1); !errors.Is(err, errWrongGroupId) ||
		errors.Is(err, errWrongEpoch) {
		t.Fatalf("a content wrong in both its group id and its epoch: got %v, want errWrongGroupId alone", err)
	}
	// every spelling of an absent group id, for emptyByteSpellings' reason: a rule written on
	// == nil accepts two of the three
	for _, empty := range emptyByteSpellings() {
		if err := CheckFramedContentContext(content, empty.value, content.Epoch); !errors.Is(err, errWrongGroupId) {
			t.Errorf("a group id that is %s: got %v, want errWrongGroupId", empty.what, err)
		}
		// and the mirror: a CONTENT carrying no group id, judged against a real one. a rule
		// that compared lengths and called two zero lengths equal accepts this pair the other
		// way round.
		blank := framingTestMemberContent()
		blank.GroupId = empty.value
		if err := CheckFramedContentContext(blank, content.GroupId, blank.Epoch); !errors.Is(err, errWrongGroupId) {
			t.Errorf("a content whose own group id is %s: got %v, want errWrongGroupId", empty.what, err)
		}
		// two absent ids ARE the same group id. whether an empty group id is legal at all is
		// the group's business and not this rule's, and a rule that answered it here would be
		// refusing a message for a reason it cannot see.
		if err := CheckFramedContentContext(blank, empty.value, blank.Epoch); err != nil {
			t.Errorf("two group ids that are both %s: got %v, want them accepted as equal", empty.what, err)
		}
	}
}

// TestFramedContentContextRefusesWrongEpoch is ValSem003 over framingNeighbouringEpochs, with
// which rows are expected to refuse DERIVED from the epoch rather than written beside them.
//
// Derived because that is what makes the table safe to extend: a row added to the neighbours is
// judged by the same one line that judges the others, so a case whose expectation somebody would
// have had to type cannot be typed wrong.
func TestFramedContentContextRefusesWrongEpoch(t *testing.T) {
	content := framingTestMemberContent()
	refused := 0
	accepted := 0
	for _, epoch := range framingNeighbouringEpochs(content.Epoch) {
		err := CheckFramedContentContext(content, content.GroupId, epoch)
		if epoch == content.Epoch {
			if err != nil {
				t.Fatalf("this content's own epoch %d was refused: %v", epoch, err)
			}
			accepted += 1
			continue
		}
		if !errors.Is(err, errWrongEpoch) {
			t.Fatalf("epoch %d against this content's %d: got %v, want errWrongEpoch",
				epoch, content.Epoch, err)
		}
		// the group id matches on every row, so ValSem002 must not be what answered
		if errors.Is(err, errWrongGroupId) {
			t.Fatalf("epoch %d answered errWrongGroupId, and the group id matches", epoch)
		}
		refused += 1
	}
	// counted, because a neighbour list that stopped producing rows leaves this loop running
	// zero times and reporting PASS, which is the one outcome a sweep must not be able to reach
	if refused == 0 || accepted != 1 {
		t.Fatalf("%d epochs refused and %d accepted, so this sweep states nothing about the rule",
			refused, accepted)
	}
	// the refusal names both epochs. a receiver holding a message from another epoch has to
	// decide whether to buffer it or drop it, and "wrong epoch" alone does not answer that.
	err := CheckFramedContentContext(content, content.GroupId, content.Epoch+1)
	for _, named := range []uint64{content.Epoch, content.Epoch + 1} {
		if !strings.Contains(err.Error(), strconv.FormatUint(named, 10)) {
			t.Errorf("the ValSem003 refusal reads %q and does not name epoch %d; a caller told only that the epoch was wrong has to decode the message again to find out which way",
				err, named)
		}
	}
}

// TestFramedContentContextRefusesANilContent holds the guard that keeps a receive path's own bug
// from becoming a nil dereference inside this package.
//
// nil_argument_test.go sweeps this along with every other nil refusal the package makes and is
// where that class is derived. What this adds is the pairing: the SAME call with a content present
// answers about the context rather than about the argument, so the guard cannot be passing by
// refusing everything.
func TestFramedContentContextRefusesANilContent(t *testing.T) {
	content := framingTestMemberContent()
	if err := CheckFramedContentContext(nil, content.GroupId, content.Epoch); !errors.Is(err, errNilFramedContent) {
		t.Fatalf("a nil content: got %v, want errNilFramedContent", err)
	}
	if err := CheckFramedContentContext(content, content.GroupId, content.Epoch); err != nil {
		t.Fatalf("the same call with a content present: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ValSem004, the sender's leaf
// ---------------------------------------------------------------------------

// framingLeafOccupancy is the occupancy pattern ValSem004 is swept over.
//
// The blank leaves are in the MIDDLE and both ends are occupied, which is this project's most
// expensive recurring defect written as a fixture. p4's ValSem401 ran over psks[0] instead of
// psks[i]; p5 task 7's erratum loop ran over element zero; p5 task 15's sweep was tested with its
// offender at the first index it visited, so a loop bounded at x < 2 passed. A pattern whose only
// blank leaf sits at position zero, or at the last position, is a pattern all three of those bugs
// pass. TestSenderLeafRefusesBlankLeaf asserts that shape rather than trusting this comment.
func framingLeafOccupancy() []bool {
	return []bool{true, true, false, true, true, false, true, true}
}

// TestSenderLeafRefusesBlankLeaf is ValSem004 over every leaf of framingLeafOccupancy, with the
// expectation of each row read off the occupancy rather than written beside it.
func TestSenderLeafRefusesBlankLeaf(t *testing.T) {
	occupancy := framingLeafOccupancy()
	// the fixture's own shape, asserted. a blank leaf at either end is a fixture that cannot
	// see a rule which judged one position, and this is the statement of that rather than the
	// comment above it.
	if len(occupancy) < 4 {
		t.Fatalf("the occupancy fixture is %d leaves and a position sweep needs a run", len(occupancy))
	}
	if !occupancy[0] || !occupancy[len(occupancy)-1] {
		t.Fatal("the occupancy fixture is blank at one of its ends, so a rule that judged only the first leaf or only the last would pass this sweep")
	}
	blank := []LeafIndex{}
	for at, filled := range occupancy {
		if !filled {
			blank = append(blank, LeafIndex(at))
		}
	}
	if len(blank) < 2 {
		t.Fatalf("the occupancy fixture holds %d blank leaves and this sweep needs more than one", len(blank))
	}

	calls := 0
	leafOccupied := func(leaf LeafIndex) bool {
		calls += 1
		return int(leaf) < len(occupancy) && occupancy[leaf]
	}
	for at, filled := range occupancy {
		sender := Sender{SenderType: SenderTypeMember, LeafIndex: LeafIndex(at)}
		err := CheckSenderLeaf(sender, leafOccupied)
		if filled {
			if err != nil {
				t.Errorf("leaf %d is occupied and was refused: %v", at, err)
			}
			continue
		}
		if !errors.Is(err, errBlankSenderLeaf) {
			t.Errorf("leaf %d is blank: got %v, want errBlankSenderLeaf", at, err)
			continue
		}
		// the refusal names the leaf, so a receiver is not left walking its own tree to work
		// out which message it just dropped
		if !strings.Contains(err.Error(), strconv.Itoa(at)) {
			t.Errorf("the ValSem004 refusal for leaf %d reads %q and does not name the leaf", at, err)
		}
	}
	// the predicate was actually consulted. a rule that answered nil without calling it accepts
	// every leaf, and every "occupied" row above passes over such a rule unchanged.
	if calls == 0 {
		t.Fatal("the occupancy predicate was never called, so whatever decided the rows above was not the tree")
	}
	// a leaf past the end of the tree entirely, which is what a hostile peer writes
	beyond := Sender{SenderType: SenderTypeMember, LeafIndex: LeafIndex(len(occupancy) + 1)}
	if err := CheckSenderLeaf(beyond, leafOccupied); !errors.Is(err, errBlankSenderLeaf) {
		t.Errorf("a leaf past the end of the tree: got %v, want errBlankSenderLeaf", err)
	}
	widest := Sender{SenderType: SenderTypeMember, LeafIndex: math.MaxUint32}
	if err := CheckSenderLeaf(widest, leafOccupied); !errors.Is(err, errBlankSenderLeaf) {
		t.Errorf("the widest leaf index a uint32 holds: got %v, want errBlankSenderLeaf", err)
	}

	// every sender type that is not a member, derived off the registry rather than being the
	// one somebody thought of, each at a leaf index this rule WOULD have refused. RFC 9420
	// section 6 gives those three types no leaf, so a rule that judged their zero valued
	// LeafIndex would be answering about a field the message never carried.
	others := 0
	for _, senderType := range senderTypes(t) {
		if senderType == SenderTypeMember {
			continue
		}
		for _, at := range blank {
			sender := Sender{SenderType: senderType, LeafIndex: at}
			if err := CheckSenderLeaf(sender, leafOccupied); err != nil {
				t.Errorf("sender type %d at blank leaf %d was refused: %v; only a member carries a leaf index",
					senderType, at, err)
			}
			others += 1
		}
	}
	if others == 0 {
		t.Fatal("the sender type registry produced nothing but member, so the carve out above was never exercised")
	}
	// and the predicate itself is refused rather than dereferenced, AHEAD of the sender type: a
	// caller holding no occupancy test must not be told its non member sender was checked
	if err := CheckSenderLeaf(Sender{SenderType: SenderTypeNewMemberCommit}, nil); !errors.Is(err, errNilLeafOccupancyTest) {
		t.Errorf("a nil occupancy test under a non member sender: got %v, want errNilLeafOccupancyTest", err)
	}
}

// ---------------------------------------------------------------------------
// ValSem009, reached three ways
// ---------------------------------------------------------------------------

// TestCommitRefusesMissingConfirmationTag is ValSem009 stated as the property the two declaration
// sites' comments claim and that nothing asserted: it is ONE condition and ONE value however it is
// reached.
//
// Three layers raise it -- the verifier, the encoder and the decoder -- and each is held on its
// own next door, by TestVerifyRefusesACommitWithNoConfirmationTag and by
// TestFramedContentAuthDataRequiresAConfirmationTagOnACommit. What neither says is that the three
// answer the SAME sentinel, which is the claim errMissingConfirmationTag's comment makes and the
// one a later task splitting the condition into two values would break while leaving both of those
// tests green.
func TestCommitRefusesMissingConfirmationTag(t *testing.T) {
	crypto := newTestCrypto(t)
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("key pair: %v", err)
	}
	groupContext := framingTestGroupContext(t)
	authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPrivateMessage,
		framingTestCommitContent(), groupContext)
	if err != nil {
		t.Fatalf("sign a commit: %v", err)
	}

	// the verifier, handed a commit whose confirmation tag was never set
	if err := VerifyAuthenticatedContent(crypto, pub, authContent, groupContext); !errors.Is(err, errMissingConfirmationTag) {
		t.Fatalf("verify: got %v, want errMissingConfirmationTag", err)
	}
	// the encoder, which refuses to serialize one at all
	if err := authContent.Auth.MarshalMLS(syntax.NewWriter(), ContentTypeCommit); !errors.Is(err, errMissingConfirmationTag) {
		t.Fatalf("marshal: got %v, want errMissingConfirmationTag", err)
	}
	// and the decoder, handed the wire legal zero length tag that is the encoding of "no tag".
	// the bytes are built through the Writer rather than spliced at a computed offset: an
	// opaque<V> length prefix is one octet under 64 and two at 64, so an offset written for one
	// signature scheme addresses the wrong octet under the next.
	w := syntax.NewWriter()
	w.WriteOpaque(authContent.Auth.Signature)
	w.WriteOpaque(nil)
	emptyTagged, err := w.Bytes()
	if err != nil {
		t.Fatalf("the commit auth data this case hands the decoder: %v", err)
	}
	decoded := FramedContentAuthData{
		Signature:       []byte("untouched"),
		ConfirmationTag: []byte("untouched"),
	}
	if err := decoded.UnmarshalMLS(syntax.NewReader(emptyTagged), ContentTypeCommit); !errors.Is(err, errMissingConfirmationTag) {
		t.Fatalf("unmarshal: got %v, want errMissingConfirmationTag", err)
	}
	if !bytes.Equal(decoded.Signature, []byte("untouched")) ||
		!bytes.Equal(decoded.ConfirmationTag, []byte("untouched")) {
		t.Errorf("the refused decode wrote %+v into the caller's value; a caller left holding half a message this package rejected has a signature and a tag that were never carried together",
			decoded)
	}

	// and the positive case, so none of the three is passing by refusing every commit
	authContent.Auth.ConfirmationTag = bytes.Repeat([]byte{0x01}, crypto.HashSize())
	if err := VerifyAuthenticatedContent(crypto, pub, authContent, groupContext); err != nil {
		t.Fatalf("a commit carrying a confirmation tag was refused: %v", err)
	}
	tagged := syntax.NewWriter()
	if err := authContent.Auth.MarshalMLS(tagged, ContentTypeCommit); err != nil {
		t.Fatalf("marshalling a commit that carries its tag: %v", err)
	}
	withTag, err := tagged.Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	if err := decoded.UnmarshalMLS(syntax.NewReader(withTag), ContentTypeCommit); err != nil {
		t.Fatalf("decoding a commit that carries its tag: %v", err)
	}
	if !bytes.Equal(decoded.ConfirmationTag, authContent.Auth.ConfirmationTag) {
		t.Errorf("round tripped the tag as %x, want %x", decoded.ConfirmationTag, authContent.Auth.ConfirmationTag)
	}
}

// ---------------------------------------------------------------------------
// the refusal roster
// ---------------------------------------------------------------------------

// refusalSource is one parsed file of a package together with the two facts the roster reads off
// its NAME rather than off its contents: where it came from, and whether it is part of the test
// binary. Both halves of the roster run over a slice of these, so a synthetic control goes through
// the same code the real scan uses rather than through a second copy of it.
type refusalSource struct {
	path   string
	parsed parsedSource
	isTest bool
}

// refusalScan is what one pass over a package answers.
//
// The parts are kept separate rather than reduced to a verdict, because each of them is a way the
// scan can go quiet, and a scan that has gone quiet issues the real source exactly the clean bill
// a working one issues. An empty refusals map means no refusal site was recognised; an empty
// namedBy means no test was recognised; and either one on its own reports zero unnamed refusals.
type refusalScan struct {
	// every package level variable of the non test source that some function answers at an
	// error result, mapped to the file declaring it. this is the roster: a refusal is a value a
	// function hands back in place of an answer.
	refusals map[string]string
	// identifiers the test binary names, mapped to the test that names them -- directly, or
	// through one package level declaration of the test binary that the test itself names.
	namedBy map[string]string
	// package level variables the non test source declares and never answers at an error
	// result. outside the roster by construction, and reported so the number is visible.
	declaredNotReturned []string
}

// unnamed is the roster's verdict: the refusals no test names, sorted so the message is stable.
func (self refusalScan) unnamed() []string {
	missing := []string{}
	for name := range self.refusals {
		if _, named := self.namedBy[name]; !named {
			missing = append(missing, name)
		}
	}
	slices.Sort(missing)
	return missing
}

// errorResultPositions is the indices of a signature's results that are of type error.
//
// Positional rather than "any identifier in any return", because a package level variable can be
// answered at a non error position perfectly legitimately -- a cached table, a shared empty value
// -- and a roster that swept those in would demand a test for things that are not refusals at all.
// The control commits that shape and this gate must be seen not to report it.
func errorResultPositions(function *ast.FuncDecl) []int {
	positions := []int{}
	if function.Type.Results == nil {
		return positions
	}
	at := 0
	for _, field := range function.Type.Results.List {
		names := len(field.Names)
		if names == 0 {
			names = 1
		}
		identifier, isIdentifier := field.Type.(*ast.Ident)
		for i := 0; i < names; i += 1 {
			if isIdentifier && identifier.Name == "error" {
				positions = append(positions, at)
			}
			at += 1
		}
	}
	return positions
}

// identifiersIn is every identifier a node mentions, at any depth.
//
// At any depth, because half of this package's refusals are wrapped -- fmt.Errorf("%w: %d", errX,
// code) is the house form -- and a reader matching only a bare `return errX` sees the subset whose
// sentence happened to be short enough to fit on one line, which is a class whose membership is
// decided by formatting.
func identifiersIn(node ast.Node) map[string]bool {
	found := map[string]bool{}
	ast.Inspect(node, func(inner ast.Node) bool {
		if identifier, isIdentifier := inner.(*ast.Ident); isIdentifier {
			found[identifier.Name] = true
		}
		return true
	})
	return found
}

// packageLevelMentionsIn maps each package level declaration of one file to the identifiers it
// mentions. Functions, methods, vars, consts and types all count: a table driving a test is as
// much a naming of a sentinel as the test body is.
func packageLevelMentionsIn(parsed parsedSource, into map[string]map[string]bool) {
	for _, declaration := range parsed.file.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			name := typed.Name.Name
			if typed.Recv != nil && len(typed.Recv.List) == 1 {
				name = receiverTypeName(typed.Recv.List[0].Type) + "." + name
			}
			into[name] = identifiersIn(typed)
		case *ast.GenDecl:
			for _, spec := range typed.Specs {
				switch typedSpec := spec.(type) {
				case *ast.ValueSpec:
					for _, ident := range typedSpec.Names {
						if ident.Name != "_" {
							into[ident.Name] = identifiersIn(typedSpec)
						}
					}
				case *ast.TypeSpec:
					into[typedSpec.Name.Name] = identifiersIn(typedSpec)
				}
			}
		}
	}
}

// refusalSitesIn collects, out of one non test file, the package level variables its functions
// answer at an error result.
func refusalSitesIn(parsed parsedSource, path string, packageVars map[string]string,
	into map[string]string) {
	for _, declaration := range parsed.file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Body == nil {
			continue
		}
		positions := errorResultPositions(function)
		if len(positions) == 0 {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			statement, isReturn := node.(*ast.ReturnStmt)
			if !isReturn {
				return true
			}
			for _, at := range positions {
				// a bare `return` inside a function with named results, and a `return f()`
				// forwarding somebody else's pair, both name nothing at this position
				if at >= len(statement.Results) {
					continue
				}
				for name := range identifiersIn(statement.Results[at]) {
					if _, isPackageVar := packageVars[name]; isPackageVar {
						into[name] = path
					}
				}
			}
			return true
		})
	}
}

// scanRefusals runs the whole roster over one package's sources.
//
// The naming side reaches ONE hop past a Test function and no further, and the depth is measured
// rather than chosen. Every refusal this package makes is named either inside a Test body or
// inside one package level declaration of the test binary that a Test body names -- nil_argument
// _test.go's row table and tree math's boundary rows are the second shape, and a row driving a
// sentinel is as much a test of it as a body naming it directly. The full transitive closure over
// this package's test declarations would be a different thing: it accepts a mention arbitrarily
// far from anything a test runs, which is a roster that reports clean for a sentinel no test can
// reach.
func scanRefusals(sources []refusalSource) refusalScan {
	packageVars := map[string]string{}
	for _, source := range sources {
		if source.isTest {
			continue
		}
		for _, name := range packageLevelVarNamesIn(source.parsed) {
			packageVars[name] = source.path
		}
	}
	scan := refusalScan{refusals: map[string]string{}, namedBy: map[string]string{}}
	for _, source := range sources {
		if source.isTest {
			continue
		}
		refusalSitesIn(source.parsed, source.path, packageVars, scan.refusals)
	}
	for name := range packageVars {
		if _, isRefusal := scan.refusals[name]; !isRefusal {
			scan.declaredNotReturned = append(scan.declaredNotReturned, name)
		}
	}
	slices.Sort(scan.declaredNotReturned)

	roots := map[string]map[string]bool{}
	testDeclarations := map[string]map[string]bool{}
	for _, source := range sources {
		if !source.isTest {
			continue
		}
		packageLevelMentionsIn(source.parsed, testDeclarations)
		for _, declaration := range source.parsed.file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Recv != nil || !strings.HasPrefix(function.Name.Name, "Test") {
				continue
			}
			roots[function.Name.Name] = identifiersIn(function)
		}
	}
	// sorted so that the test CREDITED with naming a refusal is the same one on every run; the
	// verdict does not depend on it, and a message that moved between runs would read as churn
	for _, root := range slices.Sorted(maps.Keys(roots)) {
		for name := range roots[root] {
			if _, already := scan.namedBy[name]; !already {
				scan.namedBy[name] = root
			}
		}
	}
	for _, root := range slices.Sorted(maps.Keys(roots)) {
		for through := range roots[root] {
			for name := range testDeclarations[through] {
				if _, already := scan.namedBy[name]; !already {
					scan.namedBy[name] = root + " through " + through
				}
			}
		}
	}
	return scan
}

// refusalSourcesOfThisPackage parses every go file of the package directory, test files included.
// Test files are not skipped here, for the reason key_schedule_deps_test.go records next door: a
// declaration in a test file of package mls is a declaration of package mls, and the naming half
// of this roster is entirely about them.
func refusalSourcesOfThisPackage(t *testing.T) []refusalSource {
	t.Helper()
	sources := []refusalSource{}
	for _, path := range packageSourcePaths(t) {
		sources = append(sources, refusalSource{
			path:   path,
			parsed: mustParseSource(t, path),
			isTest: strings.HasSuffix(path, "_test.go"),
		})
	}
	return sources
}

// The control's production half. Four refusals and two values that are not refusals, so both
// directions of the class are committed: what the roster must include, and what it must leave out.
const refusalRosterProductionControl = `package control

import (
	"errors"
	"fmt"
)

var (
	errNamedDirectly               = errors.New("control: a test body names this")
	errNamedThroughATable          = errors.New("control: a table a test names names this")
	errNamedOnlyByAnUncalledHelper = errors.New("control: only a helper no test names names this")
	errNamedByNothing              = errors.New("control: nothing names this")
	errNeverReturned               = errors.New("control: no error result ever answers this")
	cachedTable                    = []byte("control: not an error and not a refusal")
)

func refuse(which int) ([]byte, error) {
	switch which {
	case 0:
		return nil, errNamedDirectly
	case 1:
		return nil, fmt.Errorf("%w: wrapped, which a bare identifier match does not see", errNamedThroughATable)
	case 2:
		return nil, errNamedOnlyByAnUncalledHelper
	case 3:
		return nil, errNamedByNothing
	}
	return cachedTable, nil
}

func reads() bool {
	return errNeverReturned != nil
}
`

// The control's test half: one Test naming a refusal directly and a table naming a second, and one
// helper naming a third that no Test names at all.
const refusalRosterTestControl = `package control

import "testing"

var controlTable = []error{errNamedThroughATable}

func TestControlNamesOneDirectlyAndOneThroughATable(t *testing.T) {
	if errNamedDirectly == nil || controlTable == nil {
		t.Fatal("control")
	}
}

func helperNoTestNames() error {
	return errNamedOnlyByAnUncalledHelper
}
`

// The two the control's roster must report, and no others. Written out because this is the
// control's own expected answer and not a class read off anything: a control whose expectation was
// derived from the same code it is controlling states nothing.
var refusalRosterControlUnnamed = []string{"errNamedByNothing", "errNamedOnlyByAnUncalledHelper"}

// TestEveryRefusalThisPackageShipsIsNamedByATest is the framing refusal roster, widened to the
// package because every way of fencing "framing" off is a list.
//
// The plan's draft of this test held the ten framing sentinels in a slice literal. That is the
// shape rule 5 exists for: it reports clean for the eleventh refusal, and this package has already
// grown from five validation stand ins to eight while nobody edited such a list. The two
// alternatives considered were a file name prefix, which is the join gate that exempted a file by
// base name, and a type list, which is the same enumeration one indirection out. So the class is
// every refusal the package's non test source can hand a caller, and the framing ten are a subset
// of it that no edit can drop out of.
//
// The property is that some test NAMES the refusal. Deliberately not "some test executes this
// branch": go's coverage cannot tell a branch a test drives from one it walks past, and a sentinel
// no test mentions anywhere is the failure this catches -- a refusal whose test was deleted,
// renamed away, or moved into a file the build no longer compiles.
//
// Two things keep it from reporting clean once it has stopped reading. The control is run through
// the same scanRefusals the real package goes through and must report exactly the two refusals it
// commits and neither of the two it names; and the real scan must find this task's own three
// sentinels among the refusals it read, which is what says it read framing_protect.go rather than
// an empty directory.
func TestEveryRefusalThisPackageShipsIsNamedByATest(t *testing.T) {
	control := scanRefusals([]refusalSource{
		{path: "control.go", parsed: mustParseText(t, "control.go", refusalRosterProductionControl)},
		{path: "control_test.go", parsed: mustParseText(t, "control_test.go", refusalRosterTestControl),
			isTest: true},
	})
	if got := control.unnamed(); !slices.Equal(got, refusalRosterControlUnnamed) {
		t.Fatalf("the roster read %v out of the control, want %v; a shape it lets through is a shape the real source can be written in, and a shape it reports is a refusal the real source would be failed for having",
			got, refusalRosterControlUnnamed)
	}
	if _, sweptIn := control.refusals["cachedTable"]; sweptIn {
		t.Error("the roster read the control's non error package variable as a refusal, so it is matching a return position rather than an error result")
	}
	if !slices.Contains(control.declaredNotReturned, "errNeverReturned") {
		t.Errorf("the control declares errNeverReturned and no error result answers it, and the roster did not put it outside the class: %v",
			control.declaredNotReturned)
	}

	scan := scanRefusals(refusalSourcesOfThisPackage(t))
	if len(scan.refusals) == 0 || len(scan.namedBy) == 0 {
		t.Fatalf("the scan read %d refusals and %d named identifiers out of this package, so whatever it reports below, it read nothing",
			len(scan.refusals), len(scan.namedBy))
	}
	// this task's own three, which is what says the scan reached framing_protect.go. named
	// rather than derived on purpose: it is a guard on the SCAN and not the class, and a guard
	// derived from the thing it guards guards nothing.
	for _, anchor := range []string{"errWrongGroupId", "errWrongEpoch", "errBlankSenderLeaf"} {
		if _, read := scan.refusals[anchor]; !read {
			t.Fatalf("framing_protect.go answers %s at an error result and the scan did not read it, so it read something other than this package",
				anchor)
		}
	}
	for _, name := range scan.unnamed() {
		t.Errorf("%s is a refusal %s answers and no test in this package names it; the refusal has lost its test",
			name, scan.refusals[name])
	}
	t.Logf("%d refusals watched, %d package variables outside the class because no error result answers them",
		len(scan.refusals), len(scan.declaredNotReturned))
}

// ---------------------------------------------------------------------------
// ValSem005, ValSem007, ValSem008 and ValSem010, moved off the operations they refuse
// ---------------------------------------------------------------------------
//
// Tasks 5 to 11 wrote these four beside the codecs and the operations they refuse, which is
// where each belonged while it was the only statement of its rule. They are here now because
// the roster below is what watches all ten framing refusals at once, and a roster whose subjects
// are spread over three files is a roster whose next reader has to be told where to look. Not one
// line of any of them changed in the move: what a moved test asserts is what it asserted before,
// and a move that also edited would be a rewrite nobody reviewed as one.

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
